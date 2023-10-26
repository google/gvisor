package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type addressableEndpointStateRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var addressableEndpointStatelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type addressableEndpointStatelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *addressableEndpointStateRWMutex) Lock() {
	locking.AddGLock(addressableEndpointStateprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *addressableEndpointStateRWMutex) NestedLock(i addressableEndpointStatelockNameIndex) {
	locking.AddGLock(addressableEndpointStateprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *addressableEndpointStateRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(addressableEndpointStateprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *addressableEndpointStateRWMutex) NestedUnlock(i addressableEndpointStatelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(addressableEndpointStateprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *addressableEndpointStateRWMutex) RLock() {
	locking.AddGLock(addressableEndpointStateprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *addressableEndpointStateRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(addressableEndpointStateprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *addressableEndpointStateRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *addressableEndpointStateRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *addressableEndpointStateRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var addressableEndpointStateprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func addressableEndpointStateinitLockNames() {}

func init() {
	addressableEndpointStateinitLockNames()
	addressableEndpointStateprefixIndex = locking.NewMutexClass(reflect.TypeOf(addressableEndpointStateRWMutex{}), addressableEndpointStatelockNames)
}
