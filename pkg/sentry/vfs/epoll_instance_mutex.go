package vfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type epollReadyInstanceMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *epollReadyInstanceMutex) Lock() {
	locking.AddGLock(epollReadyInstanceprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epollReadyInstanceMutex) NestedLock() {
	locking.AddGLock(epollReadyInstanceprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *epollReadyInstanceMutex) Unlock() {
	locking.DelGLock(epollReadyInstanceprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epollReadyInstanceMutex) NestedUnlock() {
	locking.DelGLock(epollReadyInstanceprefixIndex, 1)
	m.mu.Unlock()
}

var epollReadyInstanceprefixIndex *locking.MutexClass

func init() {
	epollReadyInstanceprefixIndex = locking.NewMutexClass(reflect.TypeOf(epollReadyInstanceMutex{}))
}
