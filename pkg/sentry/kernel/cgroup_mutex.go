package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type cgroupMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *cgroupMutex) Lock() {
	locking.AddGLock(cgroupprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cgroupMutex) NestedLock() {
	locking.AddGLock(cgroupprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *cgroupMutex) Unlock() {
	locking.DelGLock(cgroupprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cgroupMutex) NestedUnlock() {
	locking.DelGLock(cgroupprefixIndex, 1)
	m.mu.Unlock()
}

var cgroupprefixIndex *locking.MutexClass

func init() {
	cgroupprefixIndex = locking.NewMutexClass(reflect.TypeOf(cgroupMutex{}))
}
