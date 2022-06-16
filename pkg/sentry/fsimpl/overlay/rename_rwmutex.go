package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type renameRWMutex struct {
	mu sync.RWMutex
}

// Lock locks m.
// +checklocksignore
func (m *renameRWMutex) Lock() {
	locking.AddGLock(renameprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *renameRWMutex) NestedLock() {
	locking.AddGLock(renameprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *renameRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(renameprefixIndex, 0)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *renameRWMutex) NestedUnlock() {
	m.mu.Unlock()
	locking.DelGLock(renameprefixIndex, 1)
}

// RLock locks m for reading.
// +checklocksignore
func (m *renameRWMutex) RLock() {
	locking.AddGLock(renameprefixIndex, 0)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *renameRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(renameprefixIndex, 0)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *renameRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *renameRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *renameRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var renameprefixIndex *locking.MutexClass

func init() {
	renameprefixIndex = locking.NewMutexClass(reflect.TypeOf(renameRWMutex{}))
}
