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

// Lock locks m.
// +checklocksignore
func (m *taskRWMutex) Lock() {
	locking.AddGLock(taskprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskRWMutex) NestedLock() {
	locking.AddGLock(taskprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *taskRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(taskprefixIndex, 0)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskRWMutex) NestedUnlock() {
	m.mu.Unlock()
	locking.DelGLock(taskprefixIndex, 1)
}

// RLock locks m for reading.
// +checklocksignore
func (m *taskRWMutex) RLock() {
	locking.AddGLock(taskprefixIndex, 0)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *taskRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(taskprefixIndex, 0)
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

func init() {
	taskprefixIndex = locking.NewMutexClass(reflect.TypeOf(taskRWMutex{}))
}
