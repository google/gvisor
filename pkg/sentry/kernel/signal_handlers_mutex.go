package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type signalHandlersMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *signalHandlersMutex) Lock() {
	locking.AddGLock(signalHandlersprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *signalHandlersMutex) NestedLock() {
	locking.AddGLock(signalHandlersprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *signalHandlersMutex) Unlock() {
	locking.DelGLock(signalHandlersprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *signalHandlersMutex) NestedUnlock() {
	locking.DelGLock(signalHandlersprefixIndex, 1)
	m.mu.Unlock()
}

var signalHandlersprefixIndex *locking.MutexClass

func init() {
	signalHandlersprefixIndex = locking.NewMutexClass(reflect.TypeOf(signalHandlersMutex{}))
}
