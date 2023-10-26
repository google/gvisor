package cgroupfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type taskRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var tasklockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type tasklockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *taskRWMutex) Lock() {
	locking.AddGLock(taskprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskRWMutex) NestedLock(i tasklockNameIndex) {
	locking.AddGLock(taskprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *taskRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(taskprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskRWMutex) NestedUnlock(i tasklockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(taskprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *taskRWMutex) RLock() {
	locking.AddGLock(taskprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *taskRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(taskprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *taskRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *taskRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *taskRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var taskprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func taskinitLockNames() {}

func init() {
	taskinitLockNames()
	taskprefixIndex = locking.NewMutexClass(reflect.TypeOf(taskRWMutex{}), tasklockNames)
}
