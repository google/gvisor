package vfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type inotifyEventMutex struct {
	mu sync.Mutex
}

var inotifyEventprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var inotifyEventlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type inotifyEventlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *inotifyEventMutex) Lock() {
	locking.AddGLock(inotifyEventprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *inotifyEventMutex) NestedLock(i inotifyEventlockNameIndex) {
	locking.AddGLock(inotifyEventprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *inotifyEventMutex) Unlock() {
	locking.DelGLock(inotifyEventprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *inotifyEventMutex) NestedUnlock(i inotifyEventlockNameIndex) {
	locking.DelGLock(inotifyEventprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func inotifyEventinitLockNames() {}

func init() {
	inotifyEventinitLockNames()
	inotifyEventprefixIndex = locking.NewMutexClass(reflect.TypeOf(inotifyEventMutex{}), inotifyEventlockNames)
}
