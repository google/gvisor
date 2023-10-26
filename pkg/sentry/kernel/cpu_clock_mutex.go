package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type cpuClockMutex struct {
	mu sync.Mutex
}

var cpuClockprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var cpuClocklockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type cpuClocklockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *cpuClockMutex) Lock() {
	locking.AddGLock(cpuClockprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cpuClockMutex) NestedLock(i cpuClocklockNameIndex) {
	locking.AddGLock(cpuClockprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *cpuClockMutex) Unlock() {
	locking.DelGLock(cpuClockprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cpuClockMutex) NestedUnlock(i cpuClocklockNameIndex) {
	locking.DelGLock(cpuClockprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func cpuClockinitLockNames() {}

func init() {
	cpuClockinitLockNames()
	cpuClockprefixIndex = locking.NewMutexClass(reflect.TypeOf(cpuClockMutex{}), cpuClocklockNames)
}
