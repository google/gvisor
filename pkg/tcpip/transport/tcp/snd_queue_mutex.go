package tcp

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type sndQueueMutex struct {
	mu sync.Mutex
}

var sndQueueprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var sndQueuelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type sndQueuelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *sndQueueMutex) Lock() {
	locking.AddGLock(sndQueueprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *sndQueueMutex) NestedLock(i sndQueuelockNameIndex) {
	locking.AddGLock(sndQueueprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *sndQueueMutex) Unlock() {
	locking.DelGLock(sndQueueprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *sndQueueMutex) NestedUnlock(i sndQueuelockNameIndex) {
	locking.DelGLock(sndQueueprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func sndQueueinitLockNames() {}

func init() {
	sndQueueinitLockNames()
	sndQueueprefixIndex = locking.NewMutexClass(reflect.TypeFor[sndQueueMutex](), sndQueuelockNames)
}
