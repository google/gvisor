package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type neighborEntryRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var neighborEntrylockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type neighborEntrylockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *neighborEntryRWMutex) Lock() {
	locking.AddGLock(neighborEntryprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *neighborEntryRWMutex) NestedLock(i neighborEntrylockNameIndex) {
	locking.AddGLock(neighborEntryprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *neighborEntryRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(neighborEntryprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *neighborEntryRWMutex) NestedUnlock(i neighborEntrylockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(neighborEntryprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *neighborEntryRWMutex) RLock() {
	locking.AddGLock(neighborEntryprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *neighborEntryRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(neighborEntryprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *neighborEntryRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *neighborEntryRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *neighborEntryRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var neighborEntryprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func neighborEntryinitLockNames() {}

func init() {
	neighborEntryinitLockNames()
	neighborEntryprefixIndex = locking.NewMutexClass(reflect.TypeOf(neighborEntryRWMutex{}), neighborEntrylockNames)
}
