package signalfd

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type operationsMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *operationsMutex) Lock() {
	locking.AddGLock(operationsprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *operationsMutex) NestedLock() {
	locking.AddGLock(operationsprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *operationsMutex) Unlock() {
	locking.DelGLock(operationsprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *operationsMutex) NestedUnlock() {
	locking.DelGLock(operationsprefixIndex, 1)
	m.mu.Unlock()
}

var operationsprefixIndex *locking.MutexClass

func init() {
	operationsprefixIndex = locking.NewMutexClass(reflect.TypeOf(operationsMutex{}))
}
