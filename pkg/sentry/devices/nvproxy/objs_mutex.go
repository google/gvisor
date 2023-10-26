package nvproxy

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type objsMutex struct {
	mu sync.Mutex
}

var objsprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var objslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type objslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *objsMutex) Lock() {
	locking.AddGLock(objsprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *objsMutex) NestedLock(i objslockNameIndex) {
	locking.AddGLock(objsprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *objsMutex) Unlock() {
	locking.DelGLock(objsprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *objsMutex) NestedUnlock(i objslockNameIndex) {
	locking.DelGLock(objsprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func objsinitLockNames() {}

func init() {
	objsinitLockNames()
	objsprefixIndex = locking.NewMutexClass(reflect.TypeOf(objsMutex{}), objslockNames)
}
