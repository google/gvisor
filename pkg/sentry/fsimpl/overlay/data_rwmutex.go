package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type dataRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var datalockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type datalockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *dataRWMutex) Lock() {
	locking.AddGLock(dataprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dataRWMutex) NestedLock(i datalockNameIndex) {
	locking.AddGLock(dataprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *dataRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(dataprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dataRWMutex) NestedUnlock(i datalockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(dataprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *dataRWMutex) RLock() {
	locking.AddGLock(dataprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *dataRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(dataprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *dataRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *dataRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *dataRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var dataprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func datainitLockNames() {}

func init() {
	datainitLockNames()
	dataprefixIndex = locking.NewMutexClass(reflect.TypeOf(dataRWMutex{}), datalockNames)
}
