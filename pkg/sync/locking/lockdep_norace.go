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
func AddGLock(*MutexClass, int) {}

// DelGLock is no-op without the lockdep tag.
//
//go:inline
func DelGLock(*MutexClass, int) {}
