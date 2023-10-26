package inet

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type abstractSocketNamespaceMutex struct {
	mu sync.Mutex
}

var abstractSocketNamespaceprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var abstractSocketNamespacelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type abstractSocketNamespacelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *abstractSocketNamespaceMutex) Lock() {
	locking.AddGLock(abstractSocketNamespaceprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *abstractSocketNamespaceMutex) NestedLock(i abstractSocketNamespacelockNameIndex) {
	locking.AddGLock(abstractSocketNamespaceprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *abstractSocketNamespaceMutex) Unlock() {
	locking.DelGLock(abstractSocketNamespaceprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *abstractSocketNamespaceMutex) NestedUnlock(i abstractSocketNamespacelockNameIndex) {
	locking.DelGLock(abstractSocketNamespaceprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func abstractSocketNamespaceinitLockNames() {}

func init() {
	abstractSocketNamespaceinitLockNames()
	abstractSocketNamespaceprefixIndex = locking.NewMutexClass(reflect.TypeOf(abstractSocketNamespaceMutex{}), abstractSocketNamespacelockNames)
}
