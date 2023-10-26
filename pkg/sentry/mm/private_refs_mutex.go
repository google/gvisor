package mm

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type privateRefsMutex struct {
	mu sync.Mutex
}

var privateRefsprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var privateRefslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type privateRefslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *privateRefsMutex) Lock() {
	locking.AddGLock(privateRefsprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *privateRefsMutex) NestedLock(i privateRefslockNameIndex) {
	locking.AddGLock(privateRefsprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *privateRefsMutex) Unlock() {
	locking.DelGLock(privateRefsprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *privateRefsMutex) NestedUnlock(i privateRefslockNameIndex) {
	locking.DelGLock(privateRefsprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func privateRefsinitLockNames() {}

func init() {
	privateRefsinitLockNames()
	privateRefsprefixIndex = locking.NewMutexClass(reflect.TypeOf(privateRefsMutex{}), privateRefslockNames)
}
