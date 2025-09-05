package tcp

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type dispatcherMutex struct {
	mu sync.Mutex
}

var dispatcherprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var dispatcherlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type dispatcherlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *dispatcherMutex) Lock() {
	locking.AddGLock(dispatcherprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dispatcherMutex) NestedLock(i dispatcherlockNameIndex) {
	locking.AddGLock(dispatcherprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *dispatcherMutex) Unlock() {
	locking.DelGLock(dispatcherprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dispatcherMutex) NestedUnlock(i dispatcherlockNameIndex) {
	locking.DelGLock(dispatcherprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func dispatcherinitLockNames() {}

func init() {
	dispatcherinitLockNames()
	dispatcherprefixIndex = locking.NewMutexClass(reflect.TypeFor[dispatcherMutex](), dispatcherlockNames)
}
