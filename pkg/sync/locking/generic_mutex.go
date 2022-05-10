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

package locking

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type Mutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *Mutex) Lock() {
	locking.AddGLock(genericMarkIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *Mutex) NestedLock() {
	locking.AddGLock(genericMarkIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *Mutex) Unlock() {
	locking.DelGLock(genericMarkIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *Mutex) NestedUnlock() {
	locking.DelGLock(genericMarkIndex, 1)
	m.mu.Unlock()
}

var genericMarkIndex *locking.MutexClass

func init() {
	genericMarkIndex = locking.NewMutexClass(reflect.TypeOf(Mutex{}))
}
