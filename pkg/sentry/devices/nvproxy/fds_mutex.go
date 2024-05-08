package nvproxy

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type fdsMutex struct {
	mu sync.Mutex
}

var fdsprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var fdslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type fdslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *fdsMutex) Lock() {
	locking.AddGLock(fdsprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *fdsMutex) NestedLock(i fdslockNameIndex) {
	locking.AddGLock(fdsprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *fdsMutex) Unlock() {
	locking.DelGLock(fdsprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *fdsMutex) NestedUnlock(i fdslockNameIndex) {
	locking.DelGLock(fdsprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func fdsinitLockNames() {}

func init() {
	fdsinitLockNames()
	fdsprefixIndex = locking.NewMutexClass(reflect.TypeOf(fdsMutex{}), fdslockNames)
}
