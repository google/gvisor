package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type stackRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var stacklockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type stacklockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *stackRWMutex) Lock() {
	locking.AddGLock(stackprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *stackRWMutex) NestedLock(i stacklockNameIndex) {
	locking.AddGLock(stackprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *stackRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(stackprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *stackRWMutex) NestedUnlock(i stacklockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(stackprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *stackRWMutex) RLock() {
	locking.AddGLock(stackprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *stackRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(stackprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *stackRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *stackRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *stackRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var stackprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func stackinitLockNames() {}

func init() {
	stackinitLockNames()
	stackprefixIndex = locking.NewMutexClass(reflect.TypeOf(stackRWMutex{}), stacklockNames)
}
