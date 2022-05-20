package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type runningTasksMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *runningTasksMutex) Lock() {
	locking.AddGLock(runningTasksprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *runningTasksMutex) NestedLock() {
	locking.AddGLock(runningTasksprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *runningTasksMutex) Unlock() {
	locking.DelGLock(runningTasksprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *runningTasksMutex) NestedUnlock() {
	locking.DelGLock(runningTasksprefixIndex, 1)
	m.mu.Unlock()
}

var runningTasksprefixIndex *locking.MutexClass

func init() {
	runningTasksprefixIndex = locking.NewMutexClass(reflect.TypeOf(runningTasksMutex{}))
}
