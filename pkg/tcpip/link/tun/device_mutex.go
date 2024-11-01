package tun

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type deviceRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var devicelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type devicelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *deviceRWMutex) Lock() {
	locking.AddGLock(deviceprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *deviceRWMutex) NestedLock(i devicelockNameIndex) {
	locking.AddGLock(deviceprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *deviceRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(deviceprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *deviceRWMutex) NestedUnlock(i devicelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(deviceprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *deviceRWMutex) RLock() {
	locking.AddGLock(deviceprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *deviceRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(deviceprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *deviceRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *deviceRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *deviceRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var deviceprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func deviceinitLockNames() {}

func init() {
	deviceinitLockNames()
	deviceprefixIndex = locking.NewMutexClass(reflect.TypeOf(deviceRWMutex{}), devicelockNames)
}
