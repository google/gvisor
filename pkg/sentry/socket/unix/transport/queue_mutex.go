package transport

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type queueMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *queueMutex) Lock() {
	locking.AddGLock(queueunixQueueIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *queueMutex) NestedLock() {
	locking.AddGLock(queueunixQueueIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *queueMutex) Unlock() {
	locking.DelGLock(queueunixQueueIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *queueMutex) NestedUnlock() {
	locking.DelGLock(queueunixQueueIndex, 1)
	m.mu.Unlock()
}

var queueunixQueueIndex *locking.MutexClass

func init() {
	queueunixQueueIndex = locking.NewMutexClass(reflect.TypeOf(queueMutex{}))
}
