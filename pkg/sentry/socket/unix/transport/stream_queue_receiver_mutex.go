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

var streamQueueReceiverprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var streamQueueReceiverlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type streamQueueReceiverlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *streamQueueReceiverMutex) Lock() {
	locking.AddGLock(streamQueueReceiverprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *streamQueueReceiverMutex) NestedLock(i streamQueueReceiverlockNameIndex) {
	locking.AddGLock(streamQueueReceiverprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *streamQueueReceiverMutex) Unlock() {
	locking.DelGLock(streamQueueReceiverprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *streamQueueReceiverMutex) NestedUnlock(i streamQueueReceiverlockNameIndex) {
	locking.DelGLock(streamQueueReceiverprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func streamQueueReceiverinitLockNames() {}

func init() {
	streamQueueReceiverinitLockNames()
	streamQueueReceiverprefixIndex = locking.NewMutexClass(reflect.TypeOf(streamQueueReceiverMutex{}), streamQueueReceiverlockNames)
}
