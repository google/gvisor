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

package test

import (
	"sync"

	"gvisor.dev/gvisor/tools/checklocks/test/crosspkg"
)

func testPrivateGlobal(v *crosspkg.PrivateState) {
	crosspkg.RequirePrivateField() // +checklocksfail=must hold privateFieldMu
	crosspkg.PrivateValue = 1      // +checklocksfail=invalid field access
	crosspkg.ExcludePrivateField()
	crosspkg.LockPrivateField()
	crosspkg.RequirePrivateField()
	crosspkg.PrivateValue = 1
	crosspkg.ExcludePrivateField() // +checklocksfail=must not hold privateFieldMu
	crosspkg.UnlockPrivateField()
	crosspkg.RequirePrivateField() // +checklocksfail=must hold privateFieldMu
	crosspkg.ExcludePrivateField()

	crosspkg.RequirePrivateStruct() // +checklocksfail=must hold privateFieldStruct.mu
	v.Value = 1                     // +checklocksfail=invalid field access
	crosspkg.ExcludePrivateStruct()
	crosspkg.LockPrivateStruct()
	crosspkg.RequirePrivateStruct()
	v.Value = 1
	crosspkg.ExcludePrivateStruct() // +checklocksfail=must not hold privateFieldStruct.mu
	crosspkg.UnlockPrivateStruct()
	crosspkg.RequirePrivateStruct() // +checklocksfail=must hold privateFieldStruct.mu
	crosspkg.ExcludePrivateStruct()
}

func testPrivateGlobalNamesArePackageQualified() {
	privateFieldMu.Lock()
	crosspkg.RequirePrivateField() // +checklocksfail=must hold privateFieldMu
	crosspkg.ExcludePrivateField()
	privateFieldMu.Unlock()

	privateFieldStruct.mu.Lock()
	crosspkg.RequirePrivateStruct() // +checklocksfail=must hold privateFieldStruct.mu
	crosspkg.ExcludePrivateStruct()
	privateFieldStruct.mu.Unlock()
}

var privateFieldMu sync.Mutex

var privateFieldStruct struct {
	mu sync.Mutex
}
