package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type userCountersMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *userCountersMutex) Lock() {
	locking.AddGLock(userCountersprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *userCountersMutex) NestedLock() {
	locking.AddGLock(userCountersprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *userCountersMutex) Unlock() {
	locking.DelGLock(userCountersprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *userCountersMutex) NestedUnlock() {
	locking.DelGLock(userCountersprefixIndex, 1)
	m.mu.Unlock()
}

var userCountersprefixIndex *locking.MutexClass

func init() {
	userCountersprefixIndex = locking.NewMutexClass(reflect.TypeOf(userCountersMutex{}))
}
