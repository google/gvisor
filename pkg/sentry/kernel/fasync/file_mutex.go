package fasync

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type fileMutex struct {
	mu sync.Mutex
}

var fileprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var filelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type filelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *fileMutex) Lock() {
	locking.AddGLock(fileprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *fileMutex) NestedLock(i filelockNameIndex) {
	locking.AddGLock(fileprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *fileMutex) Unlock() {
	locking.DelGLock(fileprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *fileMutex) NestedUnlock(i filelockNameIndex) {
	locking.DelGLock(fileprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func fileinitLockNames() {}

func init() {
	fileinitLockNames()
	fileprefixIndex = locking.NewMutexClass(reflect.TypeOf(fileMutex{}), filelockNames)
}
