package cgroup2fs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type pidsMutex struct {
	mu sync.Mutex
}

var pidsprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var pidslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type pidslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *pidsMutex) Lock() {
	locking.AddGLock(pidsprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pidsMutex) NestedLock(i pidslockNameIndex) {
	locking.AddGLock(pidsprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *pidsMutex) Unlock() {
	locking.DelGLock(pidsprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pidsMutex) NestedUnlock(i pidslockNameIndex) {
	locking.DelGLock(pidsprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func pidsinitLockNames() {}

func init() {
	pidsinitLockNames()
	pidsprefixIndex = locking.NewMutexClass(reflect.TypeFor[pidsMutex](), pidslockNames)
}
