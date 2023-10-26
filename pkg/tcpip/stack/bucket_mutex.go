package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type bucketRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var bucketlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type bucketlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
const (
	bucketLockOthertuple = bucketlockNameIndex(0)
)
const ()

// Lock locks m.
// +checklocksignore
func (m *bucketRWMutex) Lock() {
	locking.AddGLock(bucketprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *bucketRWMutex) NestedLock(i bucketlockNameIndex) {
	locking.AddGLock(bucketprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *bucketRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(bucketprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *bucketRWMutex) NestedUnlock(i bucketlockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(bucketprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *bucketRWMutex) RLock() {
	locking.AddGLock(bucketprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *bucketRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(bucketprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *bucketRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *bucketRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *bucketRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var bucketprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func bucketinitLockNames() { bucketlockNames = []string{"otherTuple"} }

func init() {
	bucketinitLockNames()
	bucketprefixIndex = locking.NewMutexClass(reflect.TypeOf(bucketRWMutex{}), bucketlockNames)
}
