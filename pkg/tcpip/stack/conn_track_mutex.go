package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type connTrackRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var connTracklockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type connTracklockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *connTrackRWMutex) Lock() {
	locking.AddGLock(connTrackprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *connTrackRWMutex) NestedLock(i connTracklockNameIndex) {
	locking.AddGLock(connTrackprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *connTrackRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(connTrackprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *connTrackRWMutex) NestedUnlock(i connTracklockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(connTrackprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *connTrackRWMutex) RLock() {
	locking.AddGLock(connTrackprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *connTrackRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(connTrackprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *connTrackRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *connTrackRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *connTrackRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var connTrackprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func connTrackinitLockNames() {}

func init() {
	connTrackinitLockNames()
	connTrackprefixIndex = locking.NewMutexClass(reflect.TypeOf(connTrackRWMutex{}), connTracklockNames)
}
