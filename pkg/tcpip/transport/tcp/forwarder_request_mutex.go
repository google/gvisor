package tcp

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type forwarderRequestMutex struct {
	mu sync.Mutex
}

var forwarderRequestprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var forwarderRequestlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type forwarderRequestlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *forwarderRequestMutex) Lock() {
	locking.AddGLock(forwarderRequestprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *forwarderRequestMutex) NestedLock(i forwarderRequestlockNameIndex) {
	locking.AddGLock(forwarderRequestprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *forwarderRequestMutex) Unlock() {
	locking.DelGLock(forwarderRequestprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *forwarderRequestMutex) NestedUnlock(i forwarderRequestlockNameIndex) {
	locking.DelGLock(forwarderRequestprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func forwarderRequestinitLockNames() {}

func init() {
	forwarderRequestinitLockNames()
	forwarderRequestprefixIndex = locking.NewMutexClass(reflect.TypeFor[forwarderRequestMutex](), forwarderRequestlockNames)
}
