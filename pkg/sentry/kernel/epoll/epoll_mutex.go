package epoll

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type epollMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *epollMutex) Lock() {
	locking.AddGLock(epollepollIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epollMutex) NestedLock() {
	locking.AddGLock(epollepollIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *epollMutex) Unlock() {
	locking.DelGLock(epollepollIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epollMutex) NestedUnlock() {
	locking.DelGLock(epollepollIndex, 1)
	m.mu.Unlock()
}

var epollepollIndex *locking.MutexClass

func init() {
	epollepollIndex = locking.NewMutexClass(reflect.TypeOf(epollMutex{}))
}
