package proc

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type dentriesRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var dentrieslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type dentrieslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *dentriesRWMutex) Lock() {
	locking.AddGLock(dentriesprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dentriesRWMutex) NestedLock(i dentrieslockNameIndex) {
	locking.AddGLock(dentriesprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *dentriesRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(dentriesprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dentriesRWMutex) NestedUnlock(i dentrieslockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(dentriesprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *dentriesRWMutex) RLock() {
	locking.AddGLock(dentriesprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *dentriesRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(dentriesprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *dentriesRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *dentriesRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *dentriesRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var dentriesprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func dentriesinitLockNames() {}

func init() {
	dentriesinitLockNames()
	dentriesprefixIndex = locking.NewMutexClass(reflect.TypeOf(dentriesRWMutex{}), dentrieslockNames)
}
