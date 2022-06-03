package cgroupfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type pidsControllerMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *pidsControllerMutex) Lock() {
	locking.AddGLock(pidsControllerprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pidsControllerMutex) NestedLock() {
	locking.AddGLock(pidsControllerprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *pidsControllerMutex) Unlock() {
	locking.DelGLock(pidsControllerprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pidsControllerMutex) NestedUnlock() {
	locking.DelGLock(pidsControllerprefixIndex, 1)
	m.mu.Unlock()
}

var pidsControllerprefixIndex *locking.MutexClass

func init() {
	pidsControllerprefixIndex = locking.NewMutexClass(reflect.TypeOf(pidsControllerMutex{}))
}
