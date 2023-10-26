package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type renameRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var renamelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type renamelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *renameRWMutex) Lock() {
	locking.AddGLock(renameprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *renameRWMutex) NestedLock(i renamelockNameIndex) {
	locking.AddGLock(renameprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *renameRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(renameprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *renameRWMutex) NestedUnlock(i renamelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(renameprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *renameRWMutex) RLock() {
	locking.AddGLock(renameprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *renameRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(renameprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *renameRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *renameRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *renameRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var renameprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func renameinitLockNames() {}

func init() {
	renameinitLockNames()
	renameprefixIndex = locking.NewMutexClass(reflect.TypeOf(renameRWMutex{}), renamelockNames)
}
