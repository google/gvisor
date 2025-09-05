package tcp

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type rcvQueueMutex struct {
	mu sync.Mutex
}

var rcvQueueprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var rcvQueuelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type rcvQueuelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *rcvQueueMutex) Lock() {
	locking.AddGLock(rcvQueueprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *rcvQueueMutex) NestedLock(i rcvQueuelockNameIndex) {
	locking.AddGLock(rcvQueueprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *rcvQueueMutex) Unlock() {
	locking.DelGLock(rcvQueueprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *rcvQueueMutex) NestedUnlock(i rcvQueuelockNameIndex) {
	locking.DelGLock(rcvQueueprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func rcvQueueinitLockNames() {}

func init() {
	rcvQueueinitLockNames()
	rcvQueueprefixIndex = locking.NewMutexClass(reflect.TypeFor[rcvQueueMutex](), rcvQueuelockNames)
}
