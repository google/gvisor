package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type connRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var connlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type connlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *connRWMutex) Lock() {
	locking.AddGLock(connprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *connRWMutex) NestedLock(i connlockNameIndex) {
	locking.AddGLock(connprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *connRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(connprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *connRWMutex) NestedUnlock(i connlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(connprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *connRWMutex) RLock() {
	locking.AddGLock(connprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *connRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(connprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *connRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *connRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *connRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var connprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func conninitLockNames() {}

func init() {
	conninitLockNames()
	connprefixIndex = locking.NewMutexClass(reflect.TypeOf(connRWMutex{}), connlockNames)
}
