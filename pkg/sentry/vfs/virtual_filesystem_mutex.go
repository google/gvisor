package vfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type virtualFilesystemMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *virtualFilesystemMutex) Lock() {
	locking.AddGLock(virtualFilesystemprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *virtualFilesystemMutex) NestedLock() {
	locking.AddGLock(virtualFilesystemprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *virtualFilesystemMutex) Unlock() {
	locking.DelGLock(virtualFilesystemprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *virtualFilesystemMutex) NestedUnlock() {
	locking.DelGLock(virtualFilesystemprefixIndex, 1)
	m.mu.Unlock()
}

var virtualFilesystemprefixIndex *locking.MutexClass

func init() {
	virtualFilesystemprefixIndex = locking.NewMutexClass(reflect.TypeOf(virtualFilesystemMutex{}))
}
