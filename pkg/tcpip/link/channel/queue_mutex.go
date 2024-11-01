package channel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type queueRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var queuelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type queuelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *queueRWMutex) Lock() {
	locking.AddGLock(queueprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *queueRWMutex) NestedLock(i queuelockNameIndex) {
	locking.AddGLock(queueprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *queueRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(queueprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *queueRWMutex) NestedUnlock(i queuelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(queueprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *queueRWMutex) RLock() {
	locking.AddGLock(queueprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *queueRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(queueprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *queueRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *queueRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *queueRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var queueprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func queueinitLockNames() {}

func init() {
	queueinitLockNames()
	queueprefixIndex = locking.NewMutexClass(reflect.TypeOf(queueRWMutex{}), queuelockNames)
}
