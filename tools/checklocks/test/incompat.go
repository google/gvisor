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

package test

import (
	"sync"
)

// badFieldsStruct verifies that refering invalid fields fails.
type badFieldsStruct struct {
	// +checklocks:mu
	x int // +checklocksfail
}

// redundantStruct verifies that redundant annotations fail.
type redundantStruct struct {
	mu sync.Mutex

	// +checklocks:mu
	// +checklocks:mu
	x int // +checklocksfail
}

// conflictsStruct verifies that conflicting annotations fail.
type conflictsStruct struct {
	// +checkatomicignore
	// +checkatomic
	x int // +checklocksfail

	// +checkatomic
	// +checkatomicignore
	y int // +checklocksfail
}
