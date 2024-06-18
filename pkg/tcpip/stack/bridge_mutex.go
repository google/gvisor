package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type bridgeRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var bridgelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type bridgelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *bridgeRWMutex) Lock() {
	locking.AddGLock(bridgeprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *bridgeRWMutex) NestedLock(i bridgelockNameIndex) {
	locking.AddGLock(bridgeprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *bridgeRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(bridgeprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *bridgeRWMutex) NestedUnlock(i bridgelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(bridgeprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *bridgeRWMutex) RLock() {
	locking.AddGLock(bridgeprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *bridgeRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(bridgeprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *bridgeRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *bridgeRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *bridgeRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var bridgeprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func bridgeinitLockNames() {}

func init() {
	bridgeinitLockNames()
	bridgeprefixIndex = locking.NewMutexClass(reflect.TypeOf(bridgeRWMutex{}), bridgelockNames)
}
