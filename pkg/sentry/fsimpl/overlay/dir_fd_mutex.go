package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type directoryFDMutex struct {
	mu sync.Mutex
}

var directoryFDprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var directoryFDlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type directoryFDlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *directoryFDMutex) Lock() {
	locking.AddGLock(directoryFDprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *directoryFDMutex) NestedLock(i directoryFDlockNameIndex) {
	locking.AddGLock(directoryFDprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *directoryFDMutex) Unlock() {
	locking.DelGLock(directoryFDprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *directoryFDMutex) NestedUnlock(i directoryFDlockNameIndex) {
	locking.DelGLock(directoryFDprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func directoryFDinitLockNames() {}

func init() {
	directoryFDinitLockNames()
	directoryFDprefixIndex = locking.NewMutexClass(reflect.TypeOf(directoryFDMutex{}), directoryFDlockNames)
}
