package epoll

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type epollListMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *epollListMutex) Lock() {
	locking.AddGLock(epollListepollListIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epollListMutex) NestedLock() {
	locking.AddGLock(epollListepollListIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *epollListMutex) Unlock() {
	locking.DelGLock(epollListepollListIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epollListMutex) NestedUnlock() {
	locking.DelGLock(epollListepollListIndex, 1)
	m.mu.Unlock()
}

var epollListepollListIndex *locking.MutexClass

func init() {
	epollListepollListIndex = locking.NewMutexClass(reflect.TypeOf(epollListMutex{}))
}
