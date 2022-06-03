package vfs

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
	locking.AddGLock(epollprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epollMutex) NestedLock() {
	locking.AddGLock(epollprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *epollMutex) Unlock() {
	locking.DelGLock(epollprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epollMutex) NestedUnlock() {
	locking.DelGLock(epollprefixIndex, 1)
	m.mu.Unlock()
}

var epollprefixIndex *locking.MutexClass

func init() {
	epollprefixIndex = locking.NewMutexClass(reflect.TypeOf(epollMutex{}))
}
