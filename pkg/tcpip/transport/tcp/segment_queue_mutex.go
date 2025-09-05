package tcp

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type segmentQueueMutex struct {
	mu sync.Mutex
}

var segmentQueueprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var segmentQueuelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type segmentQueuelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *segmentQueueMutex) Lock() {
	locking.AddGLock(segmentQueueprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *segmentQueueMutex) NestedLock(i segmentQueuelockNameIndex) {
	locking.AddGLock(segmentQueueprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *segmentQueueMutex) Unlock() {
	locking.DelGLock(segmentQueueprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *segmentQueueMutex) NestedUnlock(i segmentQueuelockNameIndex) {
	locking.DelGLock(segmentQueueprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func segmentQueueinitLockNames() {}

func init() {
	segmentQueueinitLockNames()
	segmentQueueprefixIndex = locking.NewMutexClass(reflect.TypeFor[segmentQueueMutex](), segmentQueuelockNames)
}
