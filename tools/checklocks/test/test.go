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

// Package test is a test package.
//
// Tests are all compilation tests in separate files.
//
// +checkalignedignore
package test

import (
	"sync"
)

// oneGuardStruct has one guarded field.
type oneGuardStruct struct {
	mu sync.Mutex
	// +checklocks:mu
	guardedField   int
	unguardedField int
}

// twoGuardStruct has two guarded fields.
type twoGuardStruct struct {
	mu sync.Mutex
	// +checklocks:mu
	guardedField1 int
	// +checklocks:mu
	guardedField2 int
}

// twoLocksStruct has two locks and two fields.
type twoLocksStruct struct {
	mu       sync.Mutex
	secondMu sync.Mutex
	// +checklocks:mu
	guardedField1 int
	// +checklocks:secondMu
	guardedField2 int
}

// twoLocksDoubleGuardStruct has two locks and a single field with two guards.
type twoLocksDoubleGuardStruct struct {
	mu       sync.Mutex
	secondMu sync.Mutex // +checklocksignore: mu is inferred as requisite.
	// +checklocks:mu
	// +checklocks:secondMu
	doubleGuardedField int
}

// nestedGuardStruct nests oneGuardStruct fields.
type nestedGuardStruct struct {
	val oneGuardStruct
	ptr *oneGuardStruct
}
