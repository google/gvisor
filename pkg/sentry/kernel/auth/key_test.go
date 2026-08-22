// Copyright 2026 The gVisor Authors.
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
	"sync"
	"testing"
)

func TestKeyPermissionsConcurrentUpdate(t *testing.T) {
	const (
		initialPerms KeyPermissions = (keyPermissionRead | keyPermissionSetAttr) << keyOwnerPermissionsShift
		newPerms     KeyPermissions = keyPermissionSetAttr<<keyOwnerPermissionsShift | keyPermissionRead<<keyOtherPermissionsShift
	)
	ns := NewRootUserNamespace()
	creds := NewRootCredentials(ns)
	var key *Key
	if err := ns.Keys.Do(func(keys *LockedKeySet) error {
		var err error
		// Do holds keys.txnMu during this synchronous callback, but
		// checklocks cannot propagate that fact through its argument.
		key, err = keys.Add("permissions", creds, initialPerms, MaxSetSize) // +checklocksignore
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Both permission sets allow reading, but through different classes.
	// The permission check must use a single snapshot of the key's bits.
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := ns.Keys.Do(func(keys *LockedKeySet) error {
			// Do holds keys.txnMu during this synchronous callback, but
			// checklocks cannot propagate that fact through its argument.
			keys.SetPerms(key, newPerms) // +checklocksignore
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	if !creds.HasKeyPermission(key, creds.PossessedKeys(nil, nil, nil), KeyRead) {
		t.Error("permission check denied reading during an update")
	}
	wg.Wait()
	if got := key.Permissions(); got != newPerms {
		t.Errorf("Permissions() = %v, want %v", got, newPerms)
	}
}
