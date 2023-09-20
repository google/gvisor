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

package linux

import (
	"fmt"
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// Keyctl implements Linux syscall keyctl(2).
func Keyctl(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	switch args[0].Int() {
	case linux.KEYCTL_GET_KEYRING_ID:
		return keyCtlGetKeyringID(t, args)
	case linux.KEYCTL_DESCRIBE:
		return keyctlDescribe(t, args)
	case linux.KEYCTL_JOIN_SESSION_KEYRING:
		return keyctlJoinSessionKeyring(t, args)
	case linux.KEYCTL_SETPERM:
		return keyctlSetPerm(t, args)
	}
	log.Debugf("Unimplemented keyctl operation: %d", args[0].Int())
	kernel.IncrementUnimplementedSyscallCounter(sysno)
	return 0, nil, linuxerr.ENOSYS
}

// keyCtlGetKeyringID implements keyctl(2) with operation
// KEYCTL_GET_KEYRING_ID.
func keyCtlGetKeyringID(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	keyID := auth.KeySerial(args[1].Int())
	var key *auth.Key
	var err error
	if keyID > 0 {
		// Not a special key ID, so return as-is.
		return uintptr(keyID), nil, nil
	}
	switch keyID {
	case linux.KEY_SPEC_SESSION_KEYRING:
		key, err = t.SessionKeyring()
	default:
		if keyID <= 0 {
			// Other special key IDs are not implemented.
			return 0, nil, linuxerr.ENOSYS
		}
		// For positive key IDs, KEYCTL_GET_KEYRING_ID can be used as an existence
		// and permissions check.
		key, err = t.LookupKey(keyID)
	}
	if err != nil {
		return 0, nil, err
	}
	return uintptr(key.ID), nil, nil
}

// keyctlDescribe implements keyctl(2) with operation KEYCTL_DESCRIBE.
func keyctlDescribe(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	keyID := auth.KeySerial(args[1].Int())
	bufPtr := args[2].Pointer()
	bufSize := args[3].SizeT()

	// Get address range to write to.
	if bufSize > math.MaxInt32 {
		bufSize = math.MaxInt32
	}

	var key *auth.Key
	var err error
	switch keyID {
	case linux.KEY_SPEC_SESSION_KEYRING:
		key, err = t.SessionKeyring()
	default:
		key, err = t.LookupKey(keyID)
	}
	if err != nil {
		return 0, nil, err
	}
	uid := t.UserNamespace().MapFromKUID(key.KUID())
	gid := t.UserNamespace().MapFromKGID(key.KGID())
	keyDesc := fmt.Sprintf("%s;%d;%d;%08x;%s\x00", key.Type(), uid, gid, uint64(key.Permissions()), key.Description)
	if bufSize > 0 {
		toWrite := uint(len(keyDesc))
		if toWrite > bufSize {
			toWrite = bufSize
		}
		_, err = t.CopyOutBytes(bufPtr, []byte(keyDesc)[:toWrite])
	}
	// The KEYCTL_DESCRIBE operation returns the length of the full string,
	// regardless of whether or not it was fully written out to userspace.
	// It includes the zero byte at the end in the returned length.
	return uintptr(len(keyDesc)), nil, err
}

// keyctlJoinSessionKeyring implements keyctl(2) with operation
// KEYCTL_JOIN_SESSION_KEYRING.
func keyctlJoinSessionKeyring(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	keyDescPtr := args[1].Pointer()
	var key *auth.Key
	var err error
	if keyDescPtr == 0 {
		// Creating an anonymous keyring.
		key, err = t.JoinSessionKeyring(nil)
	} else {
		// Joining a named keyring. Read in its description.
		var keyringDesc string
		keyringDesc, err = t.CopyInString(keyDescPtr, auth.MaxKeyDescSize)
		if err != nil {
			return 0, nil, err
		}
		key, err = t.JoinSessionKeyring(&keyringDesc)
	}
	if err != nil {
		return 0, nil, err
	}
	return uintptr(key.ID), nil, nil
}

// keyctlSetPerm implements keyctl(2) with operation KEYCTL_SETPERM.
func keyctlSetPerm(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	keyID := auth.KeySerial(args[1].Int())
	newPerms := auth.KeyPermissions(args[2].Uint64())
	var key *auth.Key
	var err error
	switch keyID {
	case linux.KEY_SPEC_SESSION_KEYRING:
		key, err = t.SessionKeyring()
	default:
		key, err = t.UserNamespace().Keys.Lookup(keyID)
	}
	if err != nil {
		return 0, nil, err
	}
	return 0, nil, t.SetPermsOnKey(key, newPerms)
}
