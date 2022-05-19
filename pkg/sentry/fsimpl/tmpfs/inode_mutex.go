package tmpfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type inodeMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *inodeMutex) Lock() {
	locking.AddGLock(inodeprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *inodeMutex) NestedLock() {
	locking.AddGLock(inodeprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *inodeMutex) Unlock() {
	locking.DelGLock(inodeprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *inodeMutex) NestedUnlock() {
	locking.DelGLock(inodeprefixIndex, 1)
	m.mu.Unlock()
}

var inodeprefixIndex *locking.MutexClass

func init() {
	inodeprefixIndex = locking.NewMutexClass(reflect.TypeOf(inodeMutex{}))
}
