package tmpfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type iterMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *iterMutex) Lock() {
	locking.AddGLock(iterprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *iterMutex) NestedLock() {
	locking.AddGLock(iterprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *iterMutex) Unlock() {
	locking.DelGLock(iterprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *iterMutex) NestedUnlock() {
	locking.DelGLock(iterprefixIndex, 1)
	m.mu.Unlock()
}

var iterprefixIndex *locking.MutexClass

func init() {
	iterprefixIndex = locking.NewMutexClass(reflect.TypeOf(iterMutex{}))
}
