package vfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type inotifyMutex struct {
	mu sync.Mutex
}

var inotifyprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var inotifylockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type inotifylockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *inotifyMutex) Lock() {
	locking.AddGLock(inotifyprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *inotifyMutex) NestedLock(i inotifylockNameIndex) {
	locking.AddGLock(inotifyprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *inotifyMutex) Unlock() {
	locking.DelGLock(inotifyprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *inotifyMutex) NestedUnlock(i inotifylockNameIndex) {
	locking.DelGLock(inotifyprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func inotifyinitLockNames() {}

func init() {
	inotifyinitLockNames()
	inotifyprefixIndex = locking.NewMutexClass(reflect.TypeOf(inotifyMutex{}), inotifylockNames)
}
