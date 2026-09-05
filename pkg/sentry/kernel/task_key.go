// Copyright 2023 The gVisor Authors.
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

package kernel

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// joinNewSessionKeyringLocked creates a new session keyring with the given
// description, and joins it immediately.
// Preconditions: t.mu is held.
//
// +checklocks:t.mu
func (t *Task) joinNewSessionKeyringLocked(newKeyDesc string, newKeyPerms auth.KeyPermissions) (*auth.Key, error) {
	var sessionKeyring *auth.Key
	err := t.UserNamespace().Keys.Do(func(keySet *auth.LockedKeySet) error {
		creds := t.Credentials()
		var err error
		sessionKeyring, err = keySet.Add(newKeyDesc, creds, newKeyPerms, int(t.Kernel().MaxKeySetSize.Load()))
		return err
	})
	if err != nil {
		return nil, err
	}
	t.Debugf("Joining newly-created session keyring with ID %d, permissions %v", sessionKeyring.ID, newKeyPerms)
	t.sessionKeyring = sessionKeyring
	return sessionKeyring, nil
}

// JoinSessionKeyring causes the task to join a keyring with the given
// key description (not ID).
// If `keyDesc` is nil, then the task joins a newly-instantiated session
// keyring instead.
func (t *Task) JoinSessionKeyring(keyDesc *string) (*auth.Key, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	creds := t.Credentials()
	possessed := creds.PossessedKeys(t.sessionKeyring, nil, nil)
	var sessionKeyring *auth.Key
	newKeyPerms := auth.DefaultUnnamedSessionKeyringPermissions
	newKeyDesc := auth.DefaultSessionKeyringName
	if keyDesc != nil {
		creds.UserNamespace.Keys.ForEach(func(k *auth.Key) bool {
			if k.Description == *keyDesc && creds.HasKeyPermission(k, possessed, auth.KeySearch) {
				sessionKeyring = k
				return true
			}
			return false
		})
		if sessionKeyring != nil {
			t.Debugf("Joining existing session keyring with ID %d", sessionKeyring.ID)
			t.sessionKeyring = sessionKeyring
			return sessionKeyring, nil
		}
		newKeyDesc = *keyDesc
		newKeyPerms = auth.DefaultNamedSessionKeyringPermissions
	}
	return t.joinNewSessionKeyringLocked(newKeyDesc, newKeyPerms)
}

// lookupKeyLocked resolves a key ID without checking permissions. The caller
// must check the permissions required by its operation. If the session keyring
// is requested but unset, it is implicitly initialized.
//
// Preconditions: t.mu is held.
//
// +checklocks:t.mu
func (t *Task) lookupKeyLocked(keyID auth.KeySerial) (*auth.Key, error) {
	if keyID == linux.KEY_SPEC_SESSION_KEYRING {
		if t.sessionKeyring == nil {
			return t.joinNewSessionKeyringLocked(auth.DefaultSessionKeyringName, auth.DefaultUnnamedSessionKeyringPermissions)
		}
		return t.sessionKeyring, nil
	}
	// The session keyring may belong to a previous user namespace.
	if key := t.sessionKeyring; key != nil && key.ID == keyID {
		return key, nil
	}
	return t.UserNamespace().Keys.Lookup(keyID)
}

// LookupKey looks up a key by ID and checks search permission using this task's
// credentials. keyID may be KEY_SPEC_SESSION_KEYRING.
func (t *Task) LookupKey(keyID auth.KeySerial) (*auth.Key, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key, err := t.lookupKeyLocked(keyID)
	if err != nil {
		return nil, err
	}
	creds := t.Credentials()
	if !creds.HasKeyPermission(key, creds.PossessedKeys(t.sessionKeyring, nil, nil), auth.KeySearch) {
		return nil, linuxerr.EACCES
	}
	return key, nil
}

// SetPermsOnKey sets the permission bits on the given key using the task's
// credentials. keyID may be KEY_SPEC_SESSION_KEYRING.
func (t *Task) SetPermsOnKey(keyID auth.KeySerial, perms auth.KeyPermissions) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	key, err := t.lookupKeyLocked(keyID)
	if err != nil {
		return err
	}
	creds := t.Credentials()
	possessed := creds.PossessedKeys(t.sessionKeyring, nil, nil)
	return creds.UserNamespace.Keys.Do(func(keySet *auth.LockedKeySet) error {
		if !creds.HasKeyPermission(key, possessed, auth.KeySetAttr) {
			return linuxerr.EACCES
		}
		keySet.SetPerms(key, perms)
		return nil
	})
}
