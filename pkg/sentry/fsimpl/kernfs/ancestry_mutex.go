package kernfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type ancestryRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var ancestrylockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type ancestrylockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *ancestryRWMutex) Lock() {
	locking.AddGLock(ancestryprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *ancestryRWMutex) NestedLock(i ancestrylockNameIndex) {
	locking.AddGLock(ancestryprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *ancestryRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(ancestryprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *ancestryRWMutex) NestedUnlock(i ancestrylockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(ancestryprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *ancestryRWMutex) RLock() {
	locking.AddGLock(ancestryprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *ancestryRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(ancestryprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *ancestryRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *ancestryRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *ancestryRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var ancestryprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func ancestryinitLockNames() {}

func init() {
	ancestryinitLockNames()
	ancestryprefixIndex = locking.NewMutexClass(reflect.TypeOf(ancestryRWMutex{}), ancestrylockNames)
}
