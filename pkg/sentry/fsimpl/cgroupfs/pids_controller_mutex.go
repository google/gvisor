package cgroupfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type pidsControllerMutex struct {
	mu sync.Mutex
}

var pidsControllerprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var pidsControllerlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type pidsControllerlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *pidsControllerMutex) Lock() {
	locking.AddGLock(pidsControllerprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pidsControllerMutex) NestedLock(i pidsControllerlockNameIndex) {
	locking.AddGLock(pidsControllerprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *pidsControllerMutex) Unlock() {
	locking.DelGLock(pidsControllerprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pidsControllerMutex) NestedUnlock(i pidsControllerlockNameIndex) {
	locking.DelGLock(pidsControllerprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func pidsControllerinitLockNames() {}

func init() {
	pidsControllerinitLockNames()
	pidsControllerprefixIndex = locking.NewMutexClass(reflect.TypeOf(pidsControllerMutex{}), pidsControllerlockNames)
}
