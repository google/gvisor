package sharedmem

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type serverEndpointRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var serverEndpointlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type serverEndpointlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *serverEndpointRWMutex) Lock() {
	locking.AddGLock(serverEndpointprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *serverEndpointRWMutex) NestedLock(i serverEndpointlockNameIndex) {
	locking.AddGLock(serverEndpointprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *serverEndpointRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(serverEndpointprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *serverEndpointRWMutex) NestedUnlock(i serverEndpointlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(serverEndpointprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *serverEndpointRWMutex) RLock() {
	locking.AddGLock(serverEndpointprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *serverEndpointRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(serverEndpointprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *serverEndpointRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *serverEndpointRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *serverEndpointRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var serverEndpointprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func serverEndpointinitLockNames() {}

func init() {
	serverEndpointinitLockNames()
	serverEndpointprefixIndex = locking.NewMutexClass(reflect.TypeOf(serverEndpointRWMutex{}), serverEndpointlockNames)
}
