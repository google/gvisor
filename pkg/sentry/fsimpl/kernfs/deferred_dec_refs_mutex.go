package kernfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type deferredDecRefsMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *deferredDecRefsMutex) Lock() {
	locking.AddGLock(deferredDecRefsprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *deferredDecRefsMutex) NestedLock() {
	locking.AddGLock(deferredDecRefsprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *deferredDecRefsMutex) Unlock() {
	locking.DelGLock(deferredDecRefsprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *deferredDecRefsMutex) NestedUnlock() {
	locking.DelGLock(deferredDecRefsprefixIndex, 1)
	m.mu.Unlock()
}

var deferredDecRefsprefixIndex *locking.MutexClass

func init() {
	deferredDecRefsprefixIndex = locking.NewMutexClass(reflect.TypeOf(deferredDecRefsMutex{}))
}
