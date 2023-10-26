package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type devMutex struct {
	mu sync.Mutex
}

var devprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var devlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type devlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *devMutex) Lock() {
	locking.AddGLock(devprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *devMutex) NestedLock(i devlockNameIndex) {
	locking.AddGLock(devprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *devMutex) Unlock() {
	locking.DelGLock(devprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *devMutex) NestedUnlock(i devlockNameIndex) {
	locking.DelGLock(devprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func devinitLockNames() {}

func init() {
	devinitLockNames()
	devprefixIndex = locking.NewMutexClass(reflect.TypeOf(devMutex{}), devlockNames)
}
