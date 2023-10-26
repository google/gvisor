package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type dirMutex struct {
	mu sync.Mutex
}

var dirprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var dirlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type dirlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
const (
	dirLockNew      = dirlockNameIndex(0)
	dirLockReplaced = dirlockNameIndex(1)
	dirLockChild    = dirlockNameIndex(2)
)
const ()

// Lock locks m.
// +checklocksignore
func (m *dirMutex) Lock() {
	locking.AddGLock(dirprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dirMutex) NestedLock(i dirlockNameIndex) {
	locking.AddGLock(dirprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *dirMutex) Unlock() {
	locking.DelGLock(dirprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dirMutex) NestedUnlock(i dirlockNameIndex) {
	locking.DelGLock(dirprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func dirinitLockNames() { dirlockNames = []string{"new", "replaced", "child"} }

func init() {
	dirinitLockNames()
	dirprefixIndex = locking.NewMutexClass(reflect.TypeOf(dirMutex{}), dirlockNames)
}
