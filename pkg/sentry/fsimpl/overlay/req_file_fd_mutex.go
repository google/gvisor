package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type regularFileFDMutex struct {
	mu sync.Mutex
}

var regularFileFDprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var regularFileFDlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type regularFileFDlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
const (
	regularFileFDLockD1 = regularFileFDlockNameIndex(0)
	regularFileFDLockD2 = regularFileFDlockNameIndex(1)
)
const ()

// Lock locks m.
// +checklocksignore
func (m *regularFileFDMutex) Lock() {
	locking.AddGLock(regularFileFDprefixIndex, -1) // escapes: lockdep.
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *regularFileFDMutex) NestedLock(i regularFileFDlockNameIndex) {
	locking.AddGLock(regularFileFDprefixIndex, int(i)) // escapes: lockdep.
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *regularFileFDMutex) Unlock() {
	locking.DelGLock(regularFileFDprefixIndex, -1) // escapes: lockdep.
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *regularFileFDMutex) NestedUnlock(i regularFileFDlockNameIndex) {
	locking.DelGLock(regularFileFDprefixIndex, int(i)) // escapes: lockdep.
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func regularFileFDinitLockNames() { regularFileFDlockNames = []string{"d1", "d2"} }

func init() {
	regularFileFDinitLockNames()
	regularFileFDprefixIndex = locking.NewMutexClass(reflect.TypeFor[regularFileFDMutex](), regularFileFDlockNames)
}
