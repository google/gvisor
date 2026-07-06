package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type cgroup2Mutex struct {
	mu sync.Mutex
}

var cgroup2prefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var cgroup2lockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type cgroup2lockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *cgroup2Mutex) Lock() {
	locking.AddGLock(cgroup2prefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cgroup2Mutex) NestedLock(i cgroup2lockNameIndex) {
	locking.AddGLock(cgroup2prefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *cgroup2Mutex) Unlock() {
	locking.DelGLock(cgroup2prefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cgroup2Mutex) NestedUnlock(i cgroup2lockNameIndex) {
	locking.DelGLock(cgroup2prefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func cgroup2initLockNames() {}

func init() {
	cgroup2initLockNames()
	cgroup2prefixIndex = locking.NewMutexClass(reflect.TypeFor[cgroup2Mutex](), cgroup2lockNames)
}
