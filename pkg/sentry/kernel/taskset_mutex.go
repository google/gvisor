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

// Lock locks m.
// +checklocksignore
func (m *taskSetRWMutex) Lock() {
	locking.AddGLock(taskSetprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskSetRWMutex) NestedLock() {
	locking.AddGLock(taskSetprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *taskSetRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(taskSetprefixIndex, 0)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskSetRWMutex) NestedUnlock() {
	m.mu.Unlock()
	locking.DelGLock(taskSetprefixIndex, 1)
}

// RLock locks m for reading.
// +checklocksignore
func (m *taskSetRWMutex) RLock() {
	locking.AddGLock(taskSetprefixIndex, 0)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *taskSetRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(taskSetprefixIndex, 0)
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

func init() {
	taskSetprefixIndex = locking.NewMutexClass(reflect.TypeOf(taskSetRWMutex{}))
}
