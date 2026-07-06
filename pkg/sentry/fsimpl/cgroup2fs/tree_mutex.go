package cgroup2fs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type treeRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var treelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type treelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *treeRWMutex) Lock() {
	locking.AddGLock(treeprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *treeRWMutex) NestedLock(i treelockNameIndex) {
	locking.AddGLock(treeprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *treeRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(treeprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *treeRWMutex) NestedUnlock(i treelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(treeprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *treeRWMutex) RLock() {
	locking.AddGLock(treeprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *treeRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(treeprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *treeRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *treeRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *treeRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var treeprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func treeinitLockNames() {}

func init() {
	treeinitLockNames()
	treeprefixIndex = locking.NewMutexClass(reflect.TypeFor[treeRWMutex](), treelockNames)
}
