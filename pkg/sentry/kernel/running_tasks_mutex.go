package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type runningTasksMutex struct {
	mu sync.Mutex
}

var runningTasksprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var runningTaskslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type runningTaskslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *runningTasksMutex) Lock() {
	locking.AddGLock(runningTasksprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *runningTasksMutex) NestedLock(i runningTaskslockNameIndex) {
	locking.AddGLock(runningTasksprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *runningTasksMutex) Unlock() {
	locking.DelGLock(runningTasksprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *runningTasksMutex) NestedUnlock(i runningTaskslockNameIndex) {
	locking.DelGLock(runningTasksprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func runningTasksinitLockNames() {}

func init() {
	runningTasksinitLockNames()
	runningTasksprefixIndex = locking.NewMutexClass(reflect.TypeOf(runningTasksMutex{}), runningTaskslockNames)
}
