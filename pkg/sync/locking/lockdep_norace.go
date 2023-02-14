// Copyright 2022 The gVisor Authors.
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

//go:build !lockdep
// +build !lockdep

package locking

import (
	"reflect"
)

type goroutineLocks map[*MutexClass]bool

// MutexClass is a stub class without the lockdep tag.
type MutexClass struct{}

// NewMutexClass is no-op without the lockdep tag.
func NewMutexClass(reflect.Type, []string) *MutexClass {
	return nil
}

// AddGLock is no-op without the lockdep tag.
//
//go:inline
func AddGLock(*MutexClassRef, *MutexClass, int) {}

// DelGLock is no-op without the lockdep tag.
//
//go:inline
func DelGLock(*MutexClassRef, *MutexClass, int) {}

// LockClassGenerator is an empty struct without the lockdep tag.
// +stateify savable
type LockClassGenerator struct {
}

// GetClass is no-op without the lockdep tag.
func (g *LockClassGenerator) GetClass(o any, lockNames []string) *MutexClass {
	return nil
}

// NewLockClassGenerator is no-op without the lockdep tag.
func NewLockClassGenerator(name string) *LockClassGenerator {
	return nil
}

// MutexClassRef is an empty struct without the lockdep tag.
type MutexClassRef struct{}

// SetClass is no-op without the lockdep tag.
func (*MutexClassRef) SetClass(*MutexClass) {}
