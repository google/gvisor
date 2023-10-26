package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type cleanupEndpointsMutex struct {
	mu sync.Mutex
}

var cleanupEndpointsprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var cleanupEndpointslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type cleanupEndpointslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *cleanupEndpointsMutex) Lock() {
	locking.AddGLock(cleanupEndpointsprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cleanupEndpointsMutex) NestedLock(i cleanupEndpointslockNameIndex) {
	locking.AddGLock(cleanupEndpointsprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *cleanupEndpointsMutex) Unlock() {
	locking.DelGLock(cleanupEndpointsprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *cleanupEndpointsMutex) NestedUnlock(i cleanupEndpointslockNameIndex) {
	locking.DelGLock(cleanupEndpointsprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func cleanupEndpointsinitLockNames() {}

func init() {
	cleanupEndpointsinitLockNames()
	cleanupEndpointsprefixIndex = locking.NewMutexClass(reflect.TypeOf(cleanupEndpointsMutex{}), cleanupEndpointslockNames)
}
