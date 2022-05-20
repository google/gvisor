package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type fdTableMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *fdTableMutex) Lock() {
	locking.AddGLock(fdTableprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *fdTableMutex) NestedLock() {
	locking.AddGLock(fdTableprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *fdTableMutex) Unlock() {
	locking.DelGLock(fdTableprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *fdTableMutex) NestedUnlock() {
	locking.DelGLock(fdTableprefixIndex, 1)
	m.mu.Unlock()
}

var fdTableprefixIndex *locking.MutexClass

func init() {
	fdTableprefixIndex = locking.NewMutexClass(reflect.TypeOf(fdTableMutex{}))
}
