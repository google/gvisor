package fasync

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type regMutex struct {
	mu sync.Mutex
}

var regprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var reglockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type reglockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *regMutex) Lock() {
	locking.AddGLock(regprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *regMutex) NestedLock(i reglockNameIndex) {
	locking.AddGLock(regprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *regMutex) Unlock() {
	locking.DelGLock(regprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *regMutex) NestedUnlock(i reglockNameIndex) {
	locking.DelGLock(regprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func reginitLockNames() {}

func init() {
	reginitLockNames()
	regprefixIndex = locking.NewMutexClass(reflect.TypeOf(regMutex{}), reglockNames)
}
