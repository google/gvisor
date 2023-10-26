package transport

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type endpointMutex struct {
	mu sync.Mutex
}

var endpointprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var endpointlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type endpointlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
const (
	endpointLockHigherid = endpointlockNameIndex(0)
)
const ()

// Lock locks m.
// +checklocksignore
func (m *endpointMutex) Lock() {
	locking.AddGLock(endpointprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *endpointMutex) NestedLock(i endpointlockNameIndex) {
	locking.AddGLock(endpointprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *endpointMutex) Unlock() {
	locking.DelGLock(endpointprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *endpointMutex) NestedUnlock(i endpointlockNameIndex) {
	locking.DelGLock(endpointprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func endpointinitLockNames() { endpointlockNames = []string{"higherID"} }

func init() {
	endpointinitLockNames()
	endpointprefixIndex = locking.NewMutexClass(reflect.TypeOf(endpointMutex{}), endpointlockNames)
}
