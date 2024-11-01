package fifo

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type queueDispatcherMutex struct {
	mu sync.Mutex
}

var queueDispatcherprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var queueDispatcherlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type queueDispatcherlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *queueDispatcherMutex) Lock() {
	locking.AddGLock(queueDispatcherprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *queueDispatcherMutex) NestedLock(i queueDispatcherlockNameIndex) {
	locking.AddGLock(queueDispatcherprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *queueDispatcherMutex) Unlock() {
	locking.DelGLock(queueDispatcherprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *queueDispatcherMutex) NestedUnlock(i queueDispatcherlockNameIndex) {
	locking.DelGLock(queueDispatcherprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func queueDispatcherinitLockNames() {}

func init() {
	queueDispatcherinitLockNames()
	queueDispatcherprefixIndex = locking.NewMutexClass(reflect.TypeOf(queueDispatcherMutex{}), queueDispatcherlockNames)
}
