package kernfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type filesystemRWMutex struct {
	mu sync.RWMutex
}

// Lock locks m.
// +checklocksignore
func (m *filesystemRWMutex) Lock() {
	locking.AddGLock(filesystemprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *filesystemRWMutex) NestedLock() {
	locking.AddGLock(filesystemprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *filesystemRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(filesystemprefixIndex, 0)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *filesystemRWMutex) NestedUnlock() {
	m.mu.Unlock()
	locking.DelGLock(filesystemprefixIndex, 1)
}

// RLock locks m for reading.
// +checklocksignore
func (m *filesystemRWMutex) RLock() {
	locking.AddGLock(filesystemprefixIndex, 0)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *filesystemRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(filesystemprefixIndex, 0)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *filesystemRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *filesystemRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *filesystemRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var filesystemprefixIndex *locking.MutexClass

func init() {
	filesystemprefixIndex = locking.NewMutexClass(reflect.TypeOf(filesystemRWMutex{}))
}
