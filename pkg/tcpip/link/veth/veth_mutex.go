package veth

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type vethRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var vethlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type vethlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *vethRWMutex) Lock() {
	locking.AddGLock(vethprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *vethRWMutex) NestedLock(i vethlockNameIndex) {
	locking.AddGLock(vethprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *vethRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(vethprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *vethRWMutex) NestedUnlock(i vethlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(vethprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *vethRWMutex) RLock() {
	locking.AddGLock(vethprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *vethRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(vethprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *vethRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *vethRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *vethRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var vethprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func vethinitLockNames() {}

func init() {
	vethinitLockNames()
	vethprefixIndex = locking.NewMutexClass(reflect.TypeOf(vethRWMutex{}), vethlockNames)
}
