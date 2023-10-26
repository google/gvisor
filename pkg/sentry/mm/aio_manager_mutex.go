package mm

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type aioManagerMutex struct {
	mu sync.Mutex
}

var aioManagerprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var aioManagerlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type aioManagerlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *aioManagerMutex) Lock() {
	locking.AddGLock(aioManagerprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *aioManagerMutex) NestedLock(i aioManagerlockNameIndex) {
	locking.AddGLock(aioManagerprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *aioManagerMutex) Unlock() {
	locking.DelGLock(aioManagerprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *aioManagerMutex) NestedUnlock(i aioManagerlockNameIndex) {
	locking.DelGLock(aioManagerprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func aioManagerinitLockNames() {}

func init() {
	aioManagerinitLockNames()
	aioManagerprefixIndex = locking.NewMutexClass(reflect.TypeOf(aioManagerMutex{}), aioManagerlockNames)
}
