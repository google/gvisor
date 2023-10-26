package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type stateConnRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var stateConnlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type stateConnlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *stateConnRWMutex) Lock() {
	locking.AddGLock(stateConnprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *stateConnRWMutex) NestedLock(i stateConnlockNameIndex) {
	locking.AddGLock(stateConnprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *stateConnRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(stateConnprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *stateConnRWMutex) NestedUnlock(i stateConnlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(stateConnprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *stateConnRWMutex) RLock() {
	locking.AddGLock(stateConnprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *stateConnRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(stateConnprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *stateConnRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *stateConnRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *stateConnRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var stateConnprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func stateConninitLockNames() {}

func init() {
	stateConninitLockNames()
	stateConnprefixIndex = locking.NewMutexClass(reflect.TypeOf(stateConnRWMutex{}), stateConnlockNames)
}
