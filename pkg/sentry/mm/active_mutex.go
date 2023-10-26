package mm

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type activeRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var activelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type activelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
const (
	activeLockForked = activelockNameIndex(0)
)
const ()

// Lock locks m.
// +checklocksignore
func (m *activeRWMutex) Lock() {
	locking.AddGLock(activeprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *activeRWMutex) NestedLock(i activelockNameIndex) {
	locking.AddGLock(activeprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *activeRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(activeprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *activeRWMutex) NestedUnlock(i activelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(activeprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *activeRWMutex) RLock() {
	locking.AddGLock(activeprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *activeRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(activeprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *activeRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *activeRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *activeRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var activeprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func activeinitLockNames() { activelockNames = []string{"forked"} }

func init() {
	activeinitLockNames()
	activeprefixIndex = locking.NewMutexClass(reflect.TypeOf(activeRWMutex{}), activelockNames)
}
