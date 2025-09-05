package tcp

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type epQueueMutex struct {
	mu sync.Mutex
}

var epQueueprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var epQueuelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type epQueuelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *epQueueMutex) Lock() {
	locking.AddGLock(epQueueprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epQueueMutex) NestedLock(i epQueuelockNameIndex) {
	locking.AddGLock(epQueueprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *epQueueMutex) Unlock() {
	locking.DelGLock(epQueueprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epQueueMutex) NestedUnlock(i epQueuelockNameIndex) {
	locking.DelGLock(epQueueprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func epQueueinitLockNames() {}

func init() {
	epQueueinitLockNames()
	epQueueprefixIndex = locking.NewMutexClass(reflect.TypeFor[epQueueMutex](), epQueuelockNames)
}
