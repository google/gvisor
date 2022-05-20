package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type taskMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *taskMutex) Lock() {
	locking.AddGLock(taskprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskMutex) NestedLock() {
	locking.AddGLock(taskprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *taskMutex) Unlock() {
	locking.DelGLock(taskprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskMutex) NestedUnlock() {
	locking.DelGLock(taskprefixIndex, 1)
	m.mu.Unlock()
}

var taskprefixIndex *locking.MutexClass

func init() {
	taskprefixIndex = locking.NewMutexClass(reflect.TypeOf(taskMutex{}))
}
