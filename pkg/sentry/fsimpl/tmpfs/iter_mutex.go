package tmpfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type iterMutex struct {
	mu sync.Mutex
}

var iterprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var iterlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type iterlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *iterMutex) Lock() {
	locking.AddGLock(iterprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *iterMutex) NestedLock(i iterlockNameIndex) {
	locking.AddGLock(iterprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *iterMutex) Unlock() {
	locking.DelGLock(iterprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *iterMutex) NestedUnlock(i iterlockNameIndex) {
	locking.DelGLock(iterprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func iterinitLockNames() {}

func init() {
	iterinitLockNames()
	iterprefixIndex = locking.NewMutexClass(reflect.TypeOf(iterMutex{}), iterlockNames)
}
