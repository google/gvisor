package fdbased

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type injectableEndpointRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var injectableEndpointlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type injectableEndpointlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *injectableEndpointRWMutex) Lock() {
	locking.AddGLock(injectableEndpointprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *injectableEndpointRWMutex) NestedLock(i injectableEndpointlockNameIndex) {
	locking.AddGLock(injectableEndpointprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *injectableEndpointRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(injectableEndpointprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *injectableEndpointRWMutex) NestedUnlock(i injectableEndpointlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(injectableEndpointprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *injectableEndpointRWMutex) RLock() {
	locking.AddGLock(injectableEndpointprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *injectableEndpointRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(injectableEndpointprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *injectableEndpointRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *injectableEndpointRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *injectableEndpointRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var injectableEndpointprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func injectableEndpointinitLockNames() {}

func init() {
	injectableEndpointinitLockNames()
	injectableEndpointprefixIndex = locking.NewMutexClass(reflect.TypeOf(injectableEndpointRWMutex{}), injectableEndpointlockNames)
}
