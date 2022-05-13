package transport

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type streamQueueReceiverMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *streamQueueReceiverMutex) Lock() {
	locking.AddGLock(streamQueueReceiverstreamQueueReceiverIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *streamQueueReceiverMutex) NestedLock() {
	locking.AddGLock(streamQueueReceiverstreamQueueReceiverIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *streamQueueReceiverMutex) Unlock() {
	locking.DelGLock(streamQueueReceiverstreamQueueReceiverIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *streamQueueReceiverMutex) NestedUnlock() {
	locking.DelGLock(streamQueueReceiverstreamQueueReceiverIndex, 1)
	m.mu.Unlock()
}

var streamQueueReceiverstreamQueueReceiverIndex *locking.MutexClass

func init() {
	streamQueueReceiverstreamQueueReceiverIndex = locking.NewMutexClass(reflect.TypeOf(streamQueueReceiverMutex{}))
}
