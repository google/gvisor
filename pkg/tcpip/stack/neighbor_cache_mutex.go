package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type neighborCacheRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var neighborCachelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type neighborCachelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *neighborCacheRWMutex) Lock() {
	locking.AddGLock(neighborCacheprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *neighborCacheRWMutex) NestedLock(i neighborCachelockNameIndex) {
	locking.AddGLock(neighborCacheprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *neighborCacheRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(neighborCacheprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *neighborCacheRWMutex) NestedUnlock(i neighborCachelockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(neighborCacheprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *neighborCacheRWMutex) RLock() {
	locking.AddGLock(neighborCacheprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *neighborCacheRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(neighborCacheprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *neighborCacheRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *neighborCacheRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *neighborCacheRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var neighborCacheprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func neighborCacheinitLockNames() {}

func init() {
	neighborCacheinitLockNames()
	neighborCacheprefixIndex = locking.NewMutexClass(reflect.TypeOf(neighborCacheRWMutex{}), neighborCachelockNames)
}
