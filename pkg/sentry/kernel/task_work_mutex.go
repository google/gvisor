package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type taskWorkMutex struct {
	mu sync.Mutex
}

var taskWorkprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var taskWorklockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type taskWorklockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *taskWorkMutex) Lock() {
	locking.AddGLock(taskWorkprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskWorkMutex) NestedLock(i taskWorklockNameIndex) {
	locking.AddGLock(taskWorkprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *taskWorkMutex) Unlock() {
	locking.DelGLock(taskWorkprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskWorkMutex) NestedUnlock(i taskWorklockNameIndex) {
	locking.DelGLock(taskWorkprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func taskWorkinitLockNames() {}

func init() {
	taskWorkinitLockNames()
	taskWorkprefixIndex = locking.NewMutexClass(reflect.TypeOf(taskWorkMutex{}), taskWorklockNames)
}
