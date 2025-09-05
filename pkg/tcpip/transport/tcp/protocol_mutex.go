package tcp

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type protocolRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var protocollockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type protocollockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *protocolRWMutex) Lock() {
	locking.AddGLock(protocolprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *protocolRWMutex) NestedLock(i protocollockNameIndex) {
	locking.AddGLock(protocolprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *protocolRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(protocolprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *protocolRWMutex) NestedUnlock(i protocollockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(protocolprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *protocolRWMutex) RLock() {
	locking.AddGLock(protocolprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *protocolRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(protocolprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *protocolRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *protocolRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *protocolRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var protocolprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func protocolinitLockNames() {}

func init() {
	protocolinitLockNames()
	protocolprefixIndex = locking.NewMutexClass(reflect.TypeFor[protocolRWMutex](), protocollockNames)
}
