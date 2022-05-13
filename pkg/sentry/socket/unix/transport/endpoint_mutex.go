package transport

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type endpointMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *endpointMutex) Lock() {
	locking.AddGLock(endpointunixEndpointIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *endpointMutex) NestedLock() {
	locking.AddGLock(endpointunixEndpointIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *endpointMutex) Unlock() {
	locking.DelGLock(endpointunixEndpointIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *endpointMutex) NestedUnlock() {
	locking.DelGLock(endpointunixEndpointIndex, 1)
	m.mu.Unlock()
}

var endpointunixEndpointIndex *locking.MutexClass

func init() {
	endpointunixEndpointIndex = locking.NewMutexClass(reflect.TypeOf(endpointMutex{}))
}
