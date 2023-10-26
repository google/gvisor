package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type routeRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var routelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type routelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *routeRWMutex) Lock() {
	locking.AddGLock(routeprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *routeRWMutex) NestedLock(i routelockNameIndex) {
	locking.AddGLock(routeprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *routeRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(routeprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *routeRWMutex) NestedUnlock(i routelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(routeprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *routeRWMutex) RLock() {
	locking.AddGLock(routeprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *routeRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(routeprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *routeRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *routeRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *routeRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var routeprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func routeinitLockNames() {}

func init() {
	routeinitLockNames()
	routeprefixIndex = locking.NewMutexClass(reflect.TypeOf(routeRWMutex{}), routelockNames)
}
