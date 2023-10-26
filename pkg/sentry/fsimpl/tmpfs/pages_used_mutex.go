package tmpfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type pagesUsedMutex struct {
	mu sync.Mutex
}

var pagesUsedprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var pagesUsedlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type pagesUsedlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *pagesUsedMutex) Lock() {
	locking.AddGLock(pagesUsedprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pagesUsedMutex) NestedLock(i pagesUsedlockNameIndex) {
	locking.AddGLock(pagesUsedprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *pagesUsedMutex) Unlock() {
	locking.DelGLock(pagesUsedprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pagesUsedMutex) NestedUnlock(i pagesUsedlockNameIndex) {
	locking.DelGLock(pagesUsedprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func pagesUsedinitLockNames() {}

func init() {
	pagesUsedinitLockNames()
	pagesUsedprefixIndex = locking.NewMutexClass(reflect.TypeOf(pagesUsedMutex{}), pagesUsedlockNames)
}
