package vfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type inotifyMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *inotifyMutex) Lock() {
	locking.AddGLock(inotifyprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *inotifyMutex) NestedLock() {
	locking.AddGLock(inotifyprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *inotifyMutex) Unlock() {
	locking.DelGLock(inotifyprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *inotifyMutex) NestedUnlock() {
	locking.DelGLock(inotifyprefixIndex, 1)
	m.mu.Unlock()
}

var inotifyprefixIndex *locking.MutexClass

func init() {
	inotifyprefixIndex = locking.NewMutexClass(reflect.TypeOf(inotifyMutex{}))
}
