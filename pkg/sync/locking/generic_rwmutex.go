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

// RWMutex is sync.RWMutex with the correctness validator.
type RWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var lockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// refering to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type lockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *RWMutex) Lock() {
	locking.AddGLock(genericMarkIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *RWMutex) NestedLock(i lockNameIndex) {
	locking.AddGLock(genericMarkIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *RWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(genericMarkIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *RWMutex) NestedUnlock(i lockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(genericMarkIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *RWMutex) RLock() {
	locking.AddGLock(genericMarkIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *RWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(genericMarkIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *RWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *RWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *RWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var genericMarkIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func initLockNames() {}

func init() {
	initLockNames()
	genericMarkIndex = locking.NewMutexClass(reflect.TypeOf(RWMutex{}), lockNames)
}
