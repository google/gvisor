package mm

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type aioManagerMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *aioManagerMutex) Lock() {
	locking.AddGLock(aioManagerprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *aioManagerMutex) NestedLock() {
	locking.AddGLock(aioManagerprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *aioManagerMutex) Unlock() {
	locking.DelGLock(aioManagerprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *aioManagerMutex) NestedUnlock() {
	locking.DelGLock(aioManagerprefixIndex, 1)
	m.mu.Unlock()
}

var aioManagerprefixIndex *locking.MutexClass

func init() {
	aioManagerprefixIndex = locking.NewMutexClass(reflect.TypeOf(aioManagerMutex{}))
}
