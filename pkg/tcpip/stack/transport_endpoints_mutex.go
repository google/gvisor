package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type transportEndpointsRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var transportEndpointslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type transportEndpointslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *transportEndpointsRWMutex) Lock() {
	locking.AddGLock(transportEndpointsprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *transportEndpointsRWMutex) NestedLock(i transportEndpointslockNameIndex) {
	locking.AddGLock(transportEndpointsprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *transportEndpointsRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(transportEndpointsprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *transportEndpointsRWMutex) NestedUnlock(i transportEndpointslockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(transportEndpointsprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *transportEndpointsRWMutex) RLock() {
	locking.AddGLock(transportEndpointsprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *transportEndpointsRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(transportEndpointsprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *transportEndpointsRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *transportEndpointsRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *transportEndpointsRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var transportEndpointsprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func transportEndpointsinitLockNames() {}

func init() {
	transportEndpointsinitLockNames()
	transportEndpointsprefixIndex = locking.NewMutexClass(reflect.TypeOf(transportEndpointsRWMutex{}), transportEndpointslockNames)
}
