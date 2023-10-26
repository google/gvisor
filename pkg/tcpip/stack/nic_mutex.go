package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type nicRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var niclockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type niclockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *nicRWMutex) Lock() {
	locking.AddGLock(nicprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *nicRWMutex) NestedLock(i niclockNameIndex) {
	locking.AddGLock(nicprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *nicRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(nicprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *nicRWMutex) NestedUnlock(i niclockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(nicprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *nicRWMutex) RLock() {
	locking.AddGLock(nicprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *nicRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(nicprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *nicRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *nicRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *nicRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var nicprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func nicinitLockNames() {}

func init() {
	nicinitLockNames()
	nicprefixIndex = locking.NewMutexClass(reflect.TypeOf(nicRWMutex{}), niclockNames)
}
