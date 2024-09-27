package pgalloc

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type aplSharedMutex struct {
	mu sync.Mutex
}

var aplSharedprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var aplSharedlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type aplSharedlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *aplSharedMutex) Lock() {
	locking.AddGLock(aplSharedprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *aplSharedMutex) NestedLock(i aplSharedlockNameIndex) {
	locking.AddGLock(aplSharedprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *aplSharedMutex) Unlock() {
	locking.DelGLock(aplSharedprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *aplSharedMutex) NestedUnlock(i aplSharedlockNameIndex) {
	locking.DelGLock(aplSharedprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func aplSharedinitLockNames() {}

func init() {
	aplSharedinitLockNames()
	aplSharedprefixIndex = locking.NewMutexClass(reflect.TypeOf(aplSharedMutex{}), aplSharedlockNames)
}
