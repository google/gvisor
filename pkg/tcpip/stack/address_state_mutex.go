package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type addressStateRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var addressStatelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type addressStatelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *addressStateRWMutex) Lock() {
	locking.AddGLock(addressStateprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *addressStateRWMutex) NestedLock(i addressStatelockNameIndex) {
	locking.AddGLock(addressStateprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *addressStateRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(addressStateprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *addressStateRWMutex) NestedUnlock(i addressStatelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(addressStateprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *addressStateRWMutex) RLock() {
	locking.AddGLock(addressStateprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *addressStateRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(addressStateprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *addressStateRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *addressStateRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *addressStateRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var addressStateprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func addressStateinitLockNames() {}

func init() {
	addressStateinitLockNames()
	addressStateprefixIndex = locking.NewMutexClass(reflect.TypeOf(addressStateRWMutex{}), addressStatelockNames)
}
