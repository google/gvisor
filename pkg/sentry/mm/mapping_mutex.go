package mm

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type mappingRWMutex struct {
	mu sync.RWMutex
}

// Lock locks m.
// +checklocksignore
func (m *mappingRWMutex) Lock() {
	locking.AddGLock(mappingprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *mappingRWMutex) NestedLock() {
	locking.AddGLock(mappingprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *mappingRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(mappingprefixIndex, 0)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *mappingRWMutex) NestedUnlock() {
	m.mu.Unlock()
	locking.DelGLock(mappingprefixIndex, 1)
}

// RLock locks m for reading.
// +checklocksignore
func (m *mappingRWMutex) RLock() {
	locking.AddGLock(mappingprefixIndex, 0)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *mappingRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(mappingprefixIndex, 0)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *mappingRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *mappingRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *mappingRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var mappingprefixIndex *locking.MutexClass

func init() {
	mappingprefixIndex = locking.NewMutexClass(reflect.TypeOf(mappingRWMutex{}))
}
