package cgroup2fs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type tasksRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var taskslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type taskslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *tasksRWMutex) Lock() {
	locking.AddGLock(tasksprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *tasksRWMutex) NestedLock(i taskslockNameIndex) {
	locking.AddGLock(tasksprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *tasksRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(tasksprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *tasksRWMutex) NestedUnlock(i taskslockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(tasksprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *tasksRWMutex) RLock() {
	locking.AddGLock(tasksprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *tasksRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(tasksprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *tasksRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *tasksRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *tasksRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var tasksprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func tasksinitLockNames() {}

func init() {
	tasksinitLockNames()
	tasksprefixIndex = locking.NewMutexClass(reflect.TypeFor[tasksRWMutex](), taskslockNames)
}
