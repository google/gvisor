package cgroup2fs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type cpuMutex struct {
	mu sync.Mutex
}

var cpuprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var cpulockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type cpulockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *cpuMutex) Lock() {
	locking.AddGLock(cpuprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cpuMutex) NestedLock(i cpulockNameIndex) {
	locking.AddGLock(cpuprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *cpuMutex) Unlock() {
	locking.DelGLock(cpuprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cpuMutex) NestedUnlock(i cpulockNameIndex) {
	locking.DelGLock(cpuprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func cpuinitLockNames() {}

func init() {
	cpuinitLockNames()
	cpuprefixIndex = locking.NewMutexClass(reflect.TypeFor[cpuMutex](), cpulockNames)
}
