package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type userCountersMutex struct {
	mu sync.Mutex
}

var userCountersprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var userCounterslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type userCounterslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *userCountersMutex) Lock() {
	locking.AddGLock(userCountersprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *userCountersMutex) NestedLock(i userCounterslockNameIndex) {
	locking.AddGLock(userCountersprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *userCountersMutex) Unlock() {
	locking.DelGLock(userCountersprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *userCountersMutex) NestedUnlock(i userCounterslockNameIndex) {
	locking.DelGLock(userCountersprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func userCountersinitLockNames() {}

func init() {
	userCountersinitLockNames()
	userCountersprefixIndex = locking.NewMutexClass(reflect.TypeOf(userCountersMutex{}), userCounterslockNames)
}
