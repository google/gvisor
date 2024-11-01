package muxed

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type endpointRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var endpointlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type endpointlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *endpointRWMutex) Lock() {
	locking.AddGLock(endpointprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *endpointRWMutex) NestedLock(i endpointlockNameIndex) {
	locking.AddGLock(endpointprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *endpointRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(endpointprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *endpointRWMutex) NestedUnlock(i endpointlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(endpointprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *endpointRWMutex) RLock() {
	locking.AddGLock(endpointprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *endpointRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(endpointprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *endpointRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *endpointRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *endpointRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var endpointprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func endpointinitLockNames() {}

func init() {
	endpointinitLockNames()
	endpointprefixIndex = locking.NewMutexClass(reflect.TypeOf(endpointRWMutex{}), endpointlockNames)
}
