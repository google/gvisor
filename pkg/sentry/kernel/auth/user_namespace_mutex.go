package auth

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type userNamespaceMutex struct {
	mu sync.Mutex
}

var userNamespaceprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var userNamespacelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type userNamespacelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
const (
	userNamespaceLockNs = userNamespacelockNameIndex(0)
)
const ()

// Lock locks m.
// +checklocksignore
func (m *userNamespaceMutex) Lock() {
	locking.AddGLock(userNamespaceprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *userNamespaceMutex) NestedLock(i userNamespacelockNameIndex) {
	locking.AddGLock(userNamespaceprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *userNamespaceMutex) Unlock() {
	locking.DelGLock(userNamespaceprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *userNamespaceMutex) NestedUnlock(i userNamespacelockNameIndex) {
	locking.DelGLock(userNamespaceprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func userNamespaceinitLockNames() { userNamespacelockNames = []string{"ns"} }

func init() {
	userNamespaceinitLockNames()
	userNamespaceprefixIndex = locking.NewMutexClass(reflect.TypeOf(userNamespaceMutex{}), userNamespacelockNames)
}
