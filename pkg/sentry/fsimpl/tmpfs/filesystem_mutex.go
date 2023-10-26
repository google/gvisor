package tmpfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type filesystemRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var filesystemlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type filesystemlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *filesystemRWMutex) Lock() {
	locking.AddGLock(filesystemprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *filesystemRWMutex) NestedLock(i filesystemlockNameIndex) {
	locking.AddGLock(filesystemprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *filesystemRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(filesystemprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *filesystemRWMutex) NestedUnlock(i filesystemlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(filesystemprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *filesystemRWMutex) RLock() {
	locking.AddGLock(filesystemprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *filesystemRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(filesystemprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *filesystemRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *filesystemRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *filesystemRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var filesystemprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func filesysteminitLockNames() {}

func init() {
	filesysteminitLockNames()
	filesystemprefixIndex = locking.NewMutexClass(reflect.TypeOf(filesystemRWMutex{}), filesystemlockNames)
}
