package tcp

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type forwarderMutex struct {
	mu sync.Mutex
}

var forwarderprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var forwarderlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type forwarderlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *forwarderMutex) Lock() {
	locking.AddGLock(forwarderprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *forwarderMutex) NestedLock(i forwarderlockNameIndex) {
	locking.AddGLock(forwarderprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *forwarderMutex) Unlock() {
	locking.DelGLock(forwarderprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *forwarderMutex) NestedUnlock(i forwarderlockNameIndex) {
	locking.DelGLock(forwarderprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func forwarderinitLockNames() {}

func init() {
	forwarderinitLockNames()
	forwarderprefixIndex = locking.NewMutexClass(reflect.TypeOf(forwarderMutex{}), forwarderlockNames)
}
