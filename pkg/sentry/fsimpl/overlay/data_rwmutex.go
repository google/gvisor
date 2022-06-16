package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type dataRWMutex struct {
	mu sync.RWMutex
}

// Lock locks m.
// +checklocksignore
func (m *dataRWMutex) Lock() {
	locking.AddGLock(dataprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dataRWMutex) NestedLock() {
	locking.AddGLock(dataprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *dataRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(dataprefixIndex, 0)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dataRWMutex) NestedUnlock() {
	m.mu.Unlock()
	locking.DelGLock(dataprefixIndex, 1)
}

// RLock locks m for reading.
// +checklocksignore
func (m *dataRWMutex) RLock() {
	locking.AddGLock(dataprefixIndex, 0)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *dataRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(dataprefixIndex, 0)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *dataRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *dataRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *dataRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var dataprefixIndex *locking.MutexClass

func init() {
	dataprefixIndex = locking.NewMutexClass(reflect.TypeOf(dataRWMutex{}))
}
