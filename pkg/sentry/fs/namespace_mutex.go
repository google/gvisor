package fs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type namespaceMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *namespaceMutex) Lock() {
	locking.AddGLock(namespaceprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *namespaceMutex) NestedLock() {
	locking.AddGLock(namespaceprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *namespaceMutex) Unlock() {
	locking.DelGLock(namespaceprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *namespaceMutex) NestedUnlock() {
	locking.DelGLock(namespaceprefixIndex, 1)
	m.mu.Unlock()
}

var namespaceprefixIndex *locking.MutexClass

func init() {
	namespaceprefixIndex = locking.NewMutexClass(reflect.TypeOf(namespaceMutex{}))
}
