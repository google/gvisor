package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type fdTableMutex struct {
	mu sync.Mutex
}

var fdTableprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var fdTablelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type fdTablelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *fdTableMutex) Lock() {
	locking.AddGLock(fdTableprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *fdTableMutex) NestedLock(i fdTablelockNameIndex) {
	locking.AddGLock(fdTableprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *fdTableMutex) Unlock() {
	locking.DelGLock(fdTableprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *fdTableMutex) NestedUnlock(i fdTablelockNameIndex) {
	locking.DelGLock(fdTableprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func fdTableinitLockNames() {}

func init() {
	fdTableinitLockNames()
	fdTableprefixIndex = locking.NewMutexClass(reflect.TypeOf(fdTableMutex{}), fdTablelockNames)
}
