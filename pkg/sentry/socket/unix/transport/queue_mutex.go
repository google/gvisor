package transport

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type queueMutex struct {
	mu sync.Mutex
}

var queueprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var queuelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type queuelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *queueMutex) Lock() {
	locking.AddGLock(queueprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *queueMutex) NestedLock(i queuelockNameIndex) {
	locking.AddGLock(queueprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *queueMutex) Unlock() {
	locking.DelGLock(queueprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *queueMutex) NestedUnlock(i queuelockNameIndex) {
	locking.DelGLock(queueprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func queueinitLockNames() {}

func init() {
	queueinitLockNames()
	queueprefixIndex = locking.NewMutexClass(reflect.TypeOf(queueMutex{}), queuelockNames)
}
