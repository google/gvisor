// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"encoding/binary"
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/rand"
)

// KeySerial is a key ID type.
// Only strictly positive IDs are valid key IDs.
// The zero ID is meaningless but is specified when creating new keyrings.
// Strictly negative IDs are used for special key IDs which are internally
// translated to real key IDs (e.g. KEY_SPEC_SESSION_KEYRING is translated
// to the caller process's session keyring).
type KeySerial int32

// KeyType is the type of a key.
// This is an enum, but is also exposed to userspace in KEYCTL_DESCRIBE.
// For this reason, it must match Linux.
type KeyType string

// List of known key types.
const (
	KeyTypeKeyring KeyType = "keyring"
	// Other types are not yet supported.
)

// KeyPermission represents a permission on a key.
type KeyPermission int

// List of known key permissions.
const (
	KeyView KeyPermission = iota
	KeyRead
	KeyWrite
	KeySearch
	KeyLink
	KeySetAttr
)

// KeyPermissions is the full set of permissions on a single Key.
type KeyPermissions uint64

const (
	// MaxKeyDescSize is the maximum size of the "Description" field of keys.
	// Corresponds to `KEY_MAX_DESC_SIZE` in Linux.
	MaxKeyDescSize = 4096

	// maxSetSize is the maximum number of a keys in a `Set`.
	// By default, Linux limits this number to 200 per non-root user.
	// Here, we limit it to 200 per Set, which is stricter.
	maxSetSize = 200
)

// Key represents a key in the keyrings subsystem.
//
// +stateify savable
type Key struct {
	// ID is the ID of the key, also often referred to as "serial number".
	// Note that key IDs passed in syscalls may be negative when they refer to
	// "special keys", sometimes also referred to as "shortcut IDs".
	// Key IDs of real instantiated keys are always > 0.
	// The key ID never changes and is unique within a KeySet (i.e. a user
	// namespace).
	// It must be chosen with cryptographic randomness to make enumeration
	// attacks harder.
	ID KeySerial

	// Description is a description of the key. It is also often referred to the
	// "name" of the key. Keys are canonically identified by their ID, but the
	// syscall ABI also allows look up keys by their description.
	// It may not be larger than `KeyMaxDescSize`.
	// Confusingly, the information returned by the KEYCTL_DESCRIBE operation,
	// which you'd think means "get the key description", actually returns a
	// superset of this `Description`.
	Description string

	// kuid is the owner of the key in the root namespace.
	// kuid is only mutable in KeySet transactions.
	kuid KUID

	// kgid is the group of the key in the root namespace.
	// kgid is only mutable in KeySet transactions.
	kgid KGID

	// perms is a bitfield of key permissions.
	// perms is only mutable in KeySet transactions.
	perms KeyPermissions
}

// Type returns the type of this key.
func (*Key) Type() KeyType {
	return KeyTypeKeyring
}

// KUID returns the KUID (owner ID) of the key.
func (k *Key) KUID() KUID { return k.kuid }

// KGID returns the KGID (group ID) of the key.
func (k *Key) KGID() KGID { return k.kgid }

// Permissions returns the permission bits of the key.
func (k *Key) Permissions() KeyPermissions { return k.perms }

// String is a human-friendly representation of the key.
// Notably, this is *not* the string returned to userspace when requested
// using `KEYCTL_DESCRIBE`.
func (k *Key) String() string {
	return fmt.Sprintf("id=%d,perms=0x%x,desc=%q", k.ID, k.perms, k.Description)
}

// Bitmasks for permission checks.
const (
	keyPossessorPermissionsMask  = 0x3f000000
	keyPossessorPermissionsShift = 24
	keyOwnerPermissionsMask      = 0x003f0000
	keyOwnerPermissionsShift     = 16
	keyGroupPermissionsMask      = 0x00003f00
	keyGroupPermissionsShift     = 8
	keyOtherPermissionsMask      = 0x0000003f
	keyOtherPermissionsShift     = 0

	keyPermissionView    = 0x00000001
	keyPermissionRead    = 0x00000002
	keyPermissionWrite   = 0x00000004
	keyPermissionSearch  = 0x00000008
	keyPermissionLink    = 0x00000010
	keyPermissionSetAttr = 0x00000020
	keyPermissionAll     = (keyPermissionView |
		keyPermissionRead |
		keyPermissionWrite |
		keyPermissionSearch |
		keyPermissionLink |
		keyPermissionSetAttr)
)

// String returns a human-readable version of the permission bits.
func (p KeyPermissions) String() string {
	var perms strings.Builder
	for i, s := range [4]struct {
		kind  string
		shift int
	}{
		{kind: "possessor", shift: keyPossessorPermissionsShift},
		{kind: "owner", shift: keyOwnerPermissionsShift},
		{kind: "group", shift: keyGroupPermissionsShift},
		{kind: "other", shift: keyOtherPermissionsShift},
	} {
		if i != 0 {
			perms.WriteRune(',')
		}
		perms.WriteString(s.kind)
		perms.WriteRune('=')
		kindPerms := p >> s.shift
		for _, b := range [6]struct {
			mask int
			r    rune
		}{
			{mask: keyPermissionView, r: 'v'},
			{mask: keyPermissionRead, r: 'r'},
			{mask: keyPermissionWrite, r: 'w'},
			{mask: keyPermissionSearch, r: 's'},
			{mask: keyPermissionLink, r: 'l'},
			{mask: keyPermissionSetAttr, r: 'a'},
		} {
			if uint64(kindPerms)&uint64(b.mask) != 0 {
				perms.WriteRune(b.r)
			} else {
				perms.WriteRune('-')
			}
		}
	}
	return fmt.Sprintf("%08x[%s]", uint64(p), perms.String())
}

// Default key settings.
const (
	// Default session keyring name.
	DefaultSessionKeyringName = "_ses"

	// Default permissions for unnamed session keyrings:
	// Possessors have full permissions.
	// Owners have view and read permissions.
	DefaultUnnamedSessionKeyringPermissions KeyPermissions = ((keyPermissionAll << keyPossessorPermissionsShift) |
		((keyPermissionView | keyPermissionRead) << keyOwnerPermissionsShift))

	// Default permissions for named session keyrings:
	// Possessors have full permissions.
	// Owners have view, read, and link permissions.
	DefaultNamedSessionKeyringPermissions KeyPermissions = ((keyPermissionAll << keyPossessorPermissionsShift) |
		((keyPermissionView | keyPermissionRead | keyPermissionLink) << keyOwnerPermissionsShift))
)

// PossessedKeys is an opaque type used during key permission check.
// When iterating over all keys, the possessed set of keys should only be
// built once. Since key possession is a recursive property, it can be
// expensive to determine. PossessedKeys holds all possessed keys at
// the time it is computed.
// PossessedKeys is short-lived; it should only live for so long as there
// are no changes to the KeySet or to any key permissions.
type PossessedKeys struct {
	// possessed is a list of possessed key IDs.
	possessed map[KeySerial]struct{}
}

// PossessedKeys returns a new fully-expanded set of PossessedKeys.
// The keys passed in are the set of keys that a task directly possesses:
// session keyring, process keyring, thread keyring. Each key may be nil.
// PossessedKeys is short-lived; it should only live for so long as there
// are no changes to the KeySet or to any key permissions.
func (c *Credentials) PossessedKeys(sessionKeyring, processKeyring, threadKeyring *Key) *PossessedKeys {
	possessed := &PossessedKeys{possessed: make(map[KeySerial]struct{})}
	for _, k := range [3]*Key{sessionKeyring, processKeyring, threadKeyring} {
		if k == nil {
			continue
		}
		// The possessor still needs "search" permission in order to actually possess anything.
		if ((k.perms&keyPossessorPermissionsMask)>>keyPossessorPermissionsShift)&keyPermissionSearch != 0 {
			possessed.possessed[k.ID] = struct{}{}
		}
	}

	// If we implement keyrings that contain other keys, this is where the
	// recursion would happen.

	return possessed
}

// HasKeyPermission returns whether the credentials grant `permission` on `k`.
//
//go:nosplit
func (c *Credentials) HasKeyPermission(k *Key, possessed *PossessedKeys, permission KeyPermission) bool {
	perms := k.perms & keyOtherPermissionsMask
	if _, ok := possessed.possessed[k.ID]; ok {
		perms |= (k.perms & keyPossessorPermissionsMask) >> keyPossessorPermissionsShift
	}
	if c.EffectiveKUID == k.kuid {
		perms |= (k.perms & keyOwnerPermissionsMask) >> keyOwnerPermissionsShift
	}
	if c.EffectiveKGID == k.kgid {
		perms |= (k.perms & keyGroupPermissionsMask) >> keyGroupPermissionsShift
	}
	switch permission {
	case KeyView:
		return perms&keyPermissionView != 0
	case KeyRead:
		return perms&keyPermissionRead != 0
	case KeyWrite:
		return perms&keyPermissionWrite != 0
	case KeySearch:
		return perms&keyPermissionSearch != 0
	case KeyLink:
		return perms&keyPermissionLink != 0
	case KeySetAttr:
		return perms&keyPermissionSetAttr != 0
	default:
		panic("unknown key permission")
	}
}

// KeySet is a set of keys.
//
// +stateify savable
type KeySet struct {
	// txnMu is used for transactionality of key changes.
	// This blocks multiple tasks for concurrently changing the keyset or the
	// permissions of any keys.
	txnMu keysetTransactionMutex `state:"nosave"`

	// mu protects the fields below.
	// Within functions on `KeySet`, `mu` may only be locked for reading.
	// Locking `mu` for writing may only be done in `LockedKeySet` functions.
	mu keysetRWMutex `state:"nosave"`

	// keys maps key IDs to the underlying Key struct.
	// It is initially nil to save on heap space.
	// It is only initialized when doing mutable transactions on it using `Do`.
	keys map[KeySerial]*Key
}

// LockedKeySet is a KeySet in a transaction.
// It exposes functions that can mutate the KeySet or its keys.
type LockedKeySet struct {
	*KeySet
}

// Do executes the given function as a transaction on the KeySet.
// It returns the error that `fn` returns.
// This is the only function where functions that lock the KeySet.mu for
// writing may be called.
func (s *KeySet) Do(fn func(*LockedKeySet) error) error {
	s.txnMu.Lock()
	defer s.txnMu.Unlock()
	ls := &LockedKeySet{s}
	ls.mu.Lock()
	if s.keys == nil {
		// Initialize the map from its zero value, if it hasn't been done yet.
		s.keys = make(map[KeySerial]*Key)
	}
	ls.mu.Unlock()
	return fn(ls)
}

// Lookup looks up a key by ID.
// Callers must exercise care to verify that the key can be accessed with
// proper credentials.
func (s *KeySet) Lookup(keyID KeySerial) (*Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, found := s.keys[keyID]
	if !found {
		return nil, linuxerr.ENOKEY
	}
	return key, nil
}

// ForEach iterates over all keys.
// If `fn` returns true, iteration stops immediately.
// Callers must exercise care to only process keys to which they have access.
func (s *KeySet) ForEach(fn func(*Key) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, key := range s.keys {
		if fn(key) {
			return
		}
	}
}

// getNewID returns a new random key ID strictly larger than zero.
// It uses cryptographic randomness in order to make enumeration attacks
// harder.
func getNewID() (KeySerial, error) {
	var newID int32
	for newID == 0 {
		if err := binary.Read(rand.Reader, binary.LittleEndian, &newID); err != nil {
			return 0, err
		}
	}
	if newID < 0 {
		newID = -newID
	}
	return KeySerial(newID), nil
}

// Add adds a new Key to the KeySet.
func (s *LockedKeySet) Add(description string, creds *Credentials, perms KeyPermissions) (*Key, error) {
	if len(description) >= MaxKeyDescSize {
		return nil, linuxerr.EINVAL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.keys) >= maxSetSize {
		return nil, linuxerr.EDQUOT
	}
	newID, err := getNewID()
	if err != nil {
		return nil, err
	}
	for s.keys[newID] != nil {
		newID, err = getNewID()
		if err != nil {
			return nil, err
		}
	}
	k := &Key{
		ID:          newID,
		Description: description,
		kuid:        creds.EffectiveKUID,
		kgid:        creds.EffectiveKGID,
		perms:       perms,
	}
	s.keys[newID] = k
	return k, nil
}

// SetPerms sets the permissions on a given key.
// The caller must have SetAttr permission on the key.
func (s *LockedKeySet) SetPerms(key *Key, newPerms KeyPermissions) {
	key.perms = newPerms
}
