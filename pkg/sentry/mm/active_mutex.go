package mm

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type activeRWMutex struct {
	mu sync.RWMutex
}

// Lock locks m.
// +checklocksignore
func (m *activeRWMutex) Lock() {
	locking.AddGLock(activeprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *activeRWMutex) NestedLock() {
	locking.AddGLock(activeprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *activeRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(activeprefixIndex, 0)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *activeRWMutex) NestedUnlock() {
	m.mu.Unlock()
	locking.DelGLock(activeprefixIndex, 1)
}

// RLock locks m for reading.
// +checklocksignore
func (m *activeRWMutex) RLock() {
	locking.AddGLock(activeprefixIndex, 0)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *activeRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(activeprefixIndex, 0)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *activeRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *activeRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *activeRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var activeprefixIndex *locking.MutexClass

func init() {
	activeprefixIndex = locking.NewMutexClass(reflect.TypeOf(activeRWMutex{}))
}
