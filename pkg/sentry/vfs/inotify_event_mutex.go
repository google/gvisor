package vfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type inotifyEventMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *inotifyEventMutex) Lock() {
	locking.AddGLock(inotifyEventprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *inotifyEventMutex) NestedLock() {
	locking.AddGLock(inotifyEventprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *inotifyEventMutex) Unlock() {
	locking.DelGLock(inotifyEventprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *inotifyEventMutex) NestedUnlock() {
	locking.DelGLock(inotifyEventprefixIndex, 1)
	m.mu.Unlock()
}

var inotifyEventprefixIndex *locking.MutexClass

func init() {
	inotifyEventprefixIndex = locking.NewMutexClass(reflect.TypeOf(inotifyEventMutex{}))
}
