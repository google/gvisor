package auth

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type keysetRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var keysetlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// refering to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type keysetlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *keysetRWMutex) Lock() {
	locking.AddGLock(keysetprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *keysetRWMutex) NestedLock(i keysetlockNameIndex) {
	locking.AddGLock(keysetprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *keysetRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(keysetprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *keysetRWMutex) NestedUnlock(i keysetlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(keysetprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *keysetRWMutex) RLock() {
	locking.AddGLock(keysetprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *keysetRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(keysetprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *keysetRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *keysetRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *keysetRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var keysetprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func keysetinitLockNames() {}

func init() {
	keysetinitLockNames()
	keysetprefixIndex = locking.NewMutexClass(reflect.TypeOf(keysetRWMutex{}), keysetlockNames)
}
