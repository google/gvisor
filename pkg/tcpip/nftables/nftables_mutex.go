package nftables

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type nfTablesRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var nfTableslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type nfTableslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *nfTablesRWMutex) Lock() {
	locking.AddGLock(nfTablesprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *nfTablesRWMutex) NestedLock(i nfTableslockNameIndex) {
	locking.AddGLock(nfTablesprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *nfTablesRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(nfTablesprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *nfTablesRWMutex) NestedUnlock(i nfTableslockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(nfTablesprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *nfTablesRWMutex) RLock() {
	locking.AddGLock(nfTablesprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *nfTablesRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(nfTablesprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *nfTablesRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *nfTablesRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *nfTablesRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var nfTablesprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func nfTablesinitLockNames() {}

func init() {
	nfTablesinitLockNames()
	nfTablesprefixIndex = locking.NewMutexClass(reflect.TypeFor[nfTablesRWMutex](), nfTableslockNames)
}
