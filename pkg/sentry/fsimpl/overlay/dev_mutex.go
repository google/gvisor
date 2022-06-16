package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type devMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *devMutex) Lock() {
	locking.AddGLock(devprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *devMutex) NestedLock() {
	locking.AddGLock(devprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *devMutex) Unlock() {
	locking.DelGLock(devprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *devMutex) NestedUnlock() {
	locking.DelGLock(devprefixIndex, 1)
	m.mu.Unlock()
}

var devprefixIndex *locking.MutexClass

func init() {
	devprefixIndex = locking.NewMutexClass(reflect.TypeOf(devMutex{}))
}
