package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type cpuClockMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *cpuClockMutex) Lock() {
	locking.AddGLock(cpuClockprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cpuClockMutex) NestedLock() {
	locking.AddGLock(cpuClockprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *cpuClockMutex) Unlock() {
	locking.DelGLock(cpuClockprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cpuClockMutex) NestedUnlock() {
	locking.DelGLock(cpuClockprefixIndex, 1)
	m.mu.Unlock()
}

var cpuClockprefixIndex *locking.MutexClass

func init() {
	cpuClockprefixIndex = locking.NewMutexClass(reflect.TypeOf(cpuClockMutex{}))
}
