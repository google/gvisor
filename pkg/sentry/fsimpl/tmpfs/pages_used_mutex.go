package tmpfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type pagesUsedMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *pagesUsedMutex) Lock() {
	locking.AddGLock(pagesUsedprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pagesUsedMutex) NestedLock() {
	locking.AddGLock(pagesUsedprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *pagesUsedMutex) Unlock() {
	locking.DelGLock(pagesUsedprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pagesUsedMutex) NestedUnlock() {
	locking.DelGLock(pagesUsedprefixIndex, 1)
	m.mu.Unlock()
}

var pagesUsedprefixIndex *locking.MutexClass

func init() {
	pagesUsedprefixIndex = locking.NewMutexClass(reflect.TypeOf(pagesUsedMutex{}))
}
