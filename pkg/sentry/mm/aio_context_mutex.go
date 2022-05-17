package mm

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type aioContextMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *aioContextMutex) Lock() {
	locking.AddGLock(aioContextprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *aioContextMutex) NestedLock() {
	locking.AddGLock(aioContextprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *aioContextMutex) Unlock() {
	locking.DelGLock(aioContextprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *aioContextMutex) NestedUnlock() {
	locking.DelGLock(aioContextprefixIndex, 1)
	m.mu.Unlock()
}

var aioContextprefixIndex *locking.MutexClass

func init() {
	aioContextprefixIndex = locking.NewMutexClass(reflect.TypeOf(aioContextMutex{}))
}
