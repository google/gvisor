package usage

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type memoryRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var memorylockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// refering to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type memorylockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *memoryRWMutex) Lock() {
	locking.AddGLock(memoryprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *memoryRWMutex) NestedLock(i memorylockNameIndex) {
	locking.AddGLock(memoryprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *memoryRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(memoryprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *memoryRWMutex) NestedUnlock(i memorylockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(memoryprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *memoryRWMutex) RLock() {
	locking.AddGLock(memoryprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *memoryRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(memoryprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *memoryRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *memoryRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *memoryRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var memoryprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func memoryinitLockNames() {}

func init() {
	memoryinitLockNames()
	memoryprefixIndex = locking.NewMutexClass(reflect.TypeOf(memoryRWMutex{}), memorylockNames)
}
