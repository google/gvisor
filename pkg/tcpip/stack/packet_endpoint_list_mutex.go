package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type packetEndpointListRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var packetEndpointListlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type packetEndpointListlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *packetEndpointListRWMutex) Lock() {
	locking.AddGLock(packetEndpointListprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *packetEndpointListRWMutex) NestedLock(i packetEndpointListlockNameIndex) {
	locking.AddGLock(packetEndpointListprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *packetEndpointListRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(packetEndpointListprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *packetEndpointListRWMutex) NestedUnlock(i packetEndpointListlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(packetEndpointListprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *packetEndpointListRWMutex) RLock() {
	locking.AddGLock(packetEndpointListprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *packetEndpointListRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(packetEndpointListprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *packetEndpointListRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *packetEndpointListRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *packetEndpointListRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var packetEndpointListprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func packetEndpointListinitLockNames() {}

func init() {
	packetEndpointListinitLockNames()
	packetEndpointListprefixIndex = locking.NewMutexClass(reflect.TypeOf(packetEndpointListRWMutex{}), packetEndpointListlockNames)
}
