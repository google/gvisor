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
		initialPerms KeyPermissions = (keyPermissionRead|keyPermissionSetAttr)<<keyOwnerPermissionsShift | keyPermissionSearch<<keyPossessorPermissionsShift
		newPerms     KeyPermissions = keyPermissionSetAttr<<keyOwnerPermissionsShift | (keyPermissionRead|keyPermissionSearch)<<keyPossessorPermissionsShift
	)
	ns := NewRootUserNamespace()
	creds := NewRootCredentials(ns)
	key, err := ns.Keys.Add("permissions", creds, initialPerms, MaxSetSize)
	if err != nil {
		t.Fatal(err)
	}
	possessed := creds.PossessedKeys(key, nil, nil)

	// Both permission sets allow reading, but through different classes.
	// The permission check must use a single snapshot of the key's bits.
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := key.SetPermsIfAllowed(creds, possessed, newPerms); err != nil {
			t.Error(err)
		}
	})
	if !creds.HasKeyPermission(key, possessed, KeyRead) {
		t.Error("permission check denied reading during an update")
	}
	wg.Wait()
	if got := key.Permissions(); got != newPerms {
		t.Errorf("Permissions() = %v, want %v", got, newPerms)
	}
}
