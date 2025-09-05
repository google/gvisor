package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type taskSetRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var taskSetlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type taskSetlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *taskSetRWMutex) Lock() {
	locking.AddGLock(taskSetprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskSetRWMutex) NestedLock(i taskSetlockNameIndex) {
	locking.AddGLock(taskSetprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *taskSetRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(taskSetprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskSetRWMutex) NestedUnlock(i taskSetlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(taskSetprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *taskSetRWMutex) RLock() {
	locking.AddGLock(taskSetprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *taskSetRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(taskSetprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *taskSetRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *taskSetRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *taskSetRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var taskSetprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func taskSetinitLockNames() {}

func init() {
	taskSetinitLockNames()
	taskSetprefixIndex = locking.NewMutexClass(reflect.TypeFor[taskSetRWMutex](), taskSetlockNames)
}
