package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type endpointsByNICRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var endpointsByNIClockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type endpointsByNIClockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *endpointsByNICRWMutex) Lock() {
	locking.AddGLock(endpointsByNICprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *endpointsByNICRWMutex) NestedLock(i endpointsByNIClockNameIndex) {
	locking.AddGLock(endpointsByNICprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *endpointsByNICRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(endpointsByNICprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *endpointsByNICRWMutex) NestedUnlock(i endpointsByNIClockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(endpointsByNICprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *endpointsByNICRWMutex) RLock() {
	locking.AddGLock(endpointsByNICprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *endpointsByNICRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(endpointsByNICprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *endpointsByNICRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *endpointsByNICRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *endpointsByNICRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var endpointsByNICprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func endpointsByNICinitLockNames() {}

func init() {
	endpointsByNICinitLockNames()
	endpointsByNICprefixIndex = locking.NewMutexClass(reflect.TypeOf(endpointsByNICRWMutex{}), endpointsByNIClockNames)
}
