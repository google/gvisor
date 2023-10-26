package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type ipTablesRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var ipTableslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type ipTableslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *ipTablesRWMutex) Lock() {
	locking.AddGLock(ipTablesprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *ipTablesRWMutex) NestedLock(i ipTableslockNameIndex) {
	locking.AddGLock(ipTablesprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *ipTablesRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(ipTablesprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *ipTablesRWMutex) NestedUnlock(i ipTableslockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(ipTablesprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *ipTablesRWMutex) RLock() {
	locking.AddGLock(ipTablesprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *ipTablesRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(ipTablesprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *ipTablesRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *ipTablesRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *ipTablesRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var ipTablesprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func ipTablesinitLockNames() {}

func init() {
	ipTablesinitLockNames()
	ipTablesprefixIndex = locking.NewMutexClass(reflect.TypeOf(ipTablesRWMutex{}), ipTableslockNames)
}
