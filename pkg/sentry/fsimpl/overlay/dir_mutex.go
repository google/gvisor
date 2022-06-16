package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type dirMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *dirMutex) Lock() {
	locking.AddGLock(dirprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dirMutex) NestedLock() {
	locking.AddGLock(dirprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *dirMutex) Unlock() {
	locking.DelGLock(dirprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dirMutex) NestedUnlock() {
	locking.DelGLock(dirprefixIndex, 1)
	m.mu.Unlock()
}

var dirprefixIndex *locking.MutexClass

func init() {
	dirprefixIndex = locking.NewMutexClass(reflect.TypeOf(dirMutex{}))
}
