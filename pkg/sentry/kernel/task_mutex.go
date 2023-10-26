package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type taskMutex struct {
	mu sync.Mutex
}

var taskprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var tasklockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type tasklockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
const (
	taskLockChild = tasklockNameIndex(0)
)
const ()

// Lock locks m.
// +checklocksignore
func (m *taskMutex) Lock() {
	locking.AddGLock(taskprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskMutex) NestedLock(i tasklockNameIndex) {
	locking.AddGLock(taskprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *taskMutex) Unlock() {
	locking.DelGLock(taskprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *taskMutex) NestedUnlock(i tasklockNameIndex) {
	locking.DelGLock(taskprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func taskinitLockNames() { tasklockNames = []string{"child"} }

func init() {
	taskinitLockNames()
	taskprefixIndex = locking.NewMutexClass(reflect.TypeOf(taskMutex{}), tasklockNames)
}
