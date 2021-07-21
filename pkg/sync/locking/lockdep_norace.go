// Copyright 2021 The gVisor Authors.
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

// Package locking package implements lock primitives with the correctness validator.
package locking

import (
	"reflect"
)

type goroutineLocks map[*MutexClass]bool
type MutexClass struct{}

func NewMutexClass(t reflect.Type) *MutexClass {
	return nil
}

//go:inline
func AddGLock(class *MutexClass, subclass uint32) {}

//go:inline
func DelGLock(class *MutexClass, subclass uint32) {}
