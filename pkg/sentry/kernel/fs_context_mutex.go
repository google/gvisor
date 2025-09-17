package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type fsContextMutex struct {
	mu sync.Mutex
}

var fsContextprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var fsContextlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type fsContextlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *fsContextMutex) Lock() {
	locking.AddGLock(fsContextprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *fsContextMutex) NestedLock(i fsContextlockNameIndex) {
	locking.AddGLock(fsContextprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *fsContextMutex) Unlock() {
	locking.DelGLock(fsContextprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *fsContextMutex) NestedUnlock(i fsContextlockNameIndex) {
	locking.DelGLock(fsContextprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func fsContextinitLockNames() {}

func init() {
	fsContextinitLockNames()
	fsContextprefixIndex = locking.NewMutexClass(reflect.TypeFor[fsContextMutex](), fsContextlockNames)
}
