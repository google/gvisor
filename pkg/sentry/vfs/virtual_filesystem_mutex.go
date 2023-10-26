package vfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type virtualFilesystemMutex struct {
	mu sync.Mutex
}

var virtualFilesystemprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var virtualFilesystemlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type virtualFilesystemlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *virtualFilesystemMutex) Lock() {
	locking.AddGLock(virtualFilesystemprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *virtualFilesystemMutex) NestedLock(i virtualFilesystemlockNameIndex) {
	locking.AddGLock(virtualFilesystemprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *virtualFilesystemMutex) Unlock() {
	locking.DelGLock(virtualFilesystemprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *virtualFilesystemMutex) NestedUnlock(i virtualFilesystemlockNameIndex) {
	locking.DelGLock(virtualFilesystemprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func virtualFilesysteminitLockNames() {}

func init() {
	virtualFilesysteminitLockNames()
	virtualFilesystemprefixIndex = locking.NewMutexClass(reflect.TypeOf(virtualFilesystemMutex{}), virtualFilesystemlockNames)
}
