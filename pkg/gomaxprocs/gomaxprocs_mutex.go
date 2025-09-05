package gomaxprocs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type gomaxprocsMutex struct {
	mu sync.Mutex
}

var gomaxprocsprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var gomaxprocslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type gomaxprocslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *gomaxprocsMutex) Lock() {
	locking.AddGLock(gomaxprocsprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *gomaxprocsMutex) NestedLock(i gomaxprocslockNameIndex) {
	locking.AddGLock(gomaxprocsprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *gomaxprocsMutex) Unlock() {
	locking.DelGLock(gomaxprocsprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *gomaxprocsMutex) NestedUnlock(i gomaxprocslockNameIndex) {
	locking.DelGLock(gomaxprocsprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func gomaxprocsinitLockNames() {}

func init() {
	gomaxprocsinitLockNames()
	gomaxprocsprefixIndex = locking.NewMutexClass(reflect.TypeFor[gomaxprocsMutex](), gomaxprocslockNames)
}
