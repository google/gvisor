package pgalloc

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type mappingsMutex struct {
	mu sync.Mutex
}

var mappingsprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var mappingslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type mappingslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *mappingsMutex) Lock() {
	locking.AddGLock(mappingsprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *mappingsMutex) NestedLock(i mappingslockNameIndex) {
	locking.AddGLock(mappingsprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *mappingsMutex) Unlock() {
	locking.DelGLock(mappingsprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *mappingsMutex) NestedUnlock(i mappingslockNameIndex) {
	locking.DelGLock(mappingsprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func mappingsinitLockNames() {}

func init() {
	mappingsinitLockNames()
	mappingsprefixIndex = locking.NewMutexClass(reflect.TypeOf(mappingsMutex{}), mappingslockNames)
}
