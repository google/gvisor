package pipe

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type inodeMutex struct {
	mu sync.Mutex
}

var inodeprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var inodelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type inodelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *inodeMutex) Lock() {
	locking.AddGLock(inodeprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *inodeMutex) NestedLock(i inodelockNameIndex) {
	locking.AddGLock(inodeprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *inodeMutex) Unlock() {
	locking.DelGLock(inodeprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *inodeMutex) NestedUnlock(i inodelockNameIndex) {
	locking.DelGLock(inodeprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func inodeinitLockNames() {}

func init() {
	inodeinitLockNames()
	inodeprefixIndex = locking.NewMutexClass(reflect.TypeOf(inodeMutex{}), inodelockNames)
}
