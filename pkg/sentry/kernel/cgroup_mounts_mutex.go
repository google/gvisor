package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type cgroupMountsMutex struct {
	mu sync.Mutex
}

var cgroupMountsprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var cgroupMountslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type cgroupMountslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *cgroupMountsMutex) Lock() {
	locking.AddGLock(cgroupMountsprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cgroupMountsMutex) NestedLock(i cgroupMountslockNameIndex) {
	locking.AddGLock(cgroupMountsprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *cgroupMountsMutex) Unlock() {
	locking.DelGLock(cgroupMountsprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cgroupMountsMutex) NestedUnlock(i cgroupMountslockNameIndex) {
	locking.DelGLock(cgroupMountsprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func cgroupMountsinitLockNames() {}

func init() {
	cgroupMountsinitLockNames()
	cgroupMountsprefixIndex = locking.NewMutexClass(reflect.TypeOf(cgroupMountsMutex{}), cgroupMountslockNames)
}
