package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type threadGroupTimerMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *threadGroupTimerMutex) Lock() {
	locking.AddGLock(threadGroupTimerprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *threadGroupTimerMutex) NestedLock() {
	locking.AddGLock(threadGroupTimerprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *threadGroupTimerMutex) Unlock() {
	locking.DelGLock(threadGroupTimerprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *threadGroupTimerMutex) NestedUnlock() {
	locking.DelGLock(threadGroupTimerprefixIndex, 1)
	m.mu.Unlock()
}

var threadGroupTimerprefixIndex *locking.MutexClass

func init() {
	threadGroupTimerprefixIndex = locking.NewMutexClass(reflect.TypeOf(threadGroupTimerMutex{}))
}
