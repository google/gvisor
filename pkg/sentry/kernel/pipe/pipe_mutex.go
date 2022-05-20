package pipe

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type pipeMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *pipeMutex) Lock() {
	locking.AddGLock(pipepipeIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pipeMutex) NestedLock() {
	locking.AddGLock(pipepipeIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *pipeMutex) Unlock() {
	locking.DelGLock(pipepipeIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pipeMutex) NestedUnlock() {
	locking.DelGLock(pipepipeIndex, 1)
	m.mu.Unlock()
}

var pipepipeIndex *locking.MutexClass

func init() {
	pipepipeIndex = locking.NewMutexClass(reflect.TypeOf(pipeMutex{}))
}
