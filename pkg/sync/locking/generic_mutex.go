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
//
// +stateify savable
type Mutex struct {
	subclass int
	mu       sync.Mutex `state:"nosave"`
}

var genericMarkIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var lockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type lockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

func (m *Mutex) SetSubclass(c int) {
	m.subclass = c
}

// Lock locks m.
// +checklocksignore
func (m *Mutex) Lock() {
	locking.AddGLock(genericMarkIndex, m.subclass, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *Mutex) NestedLock(i lockNameIndex) {
	locking.AddGLock(genericMarkIndex, m.subclass, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *Mutex) Unlock() {
	locking.DelGLock(genericMarkIndex, m.subclass, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *Mutex) NestedUnlock(i lockNameIndex) {
	locking.DelGLock(genericMarkIndex, m.subclass, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func initLockNames() {}

func SetSubclassNameMap(m map[int]string) {
	genericMarkIndex.SetSubclassNameMap(m)
}

func init() {
	initLockNames()
	genericMarkIndex = locking.NewMutexClass(reflect.TypeOf(Mutex{}), lockNames)
}
