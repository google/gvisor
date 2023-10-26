package mm

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type metadataMutex struct {
	mu sync.Mutex
}

var metadataprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var metadatalockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type metadatalockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *metadataMutex) Lock() {
	locking.AddGLock(metadataprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *metadataMutex) NestedLock(i metadatalockNameIndex) {
	locking.AddGLock(metadataprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *metadataMutex) Unlock() {
	locking.DelGLock(metadataprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *metadataMutex) NestedUnlock(i metadatalockNameIndex) {
	locking.DelGLock(metadataprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func metadatainitLockNames() {}

func init() {
	metadatainitLockNames()
	metadataprefixIndex = locking.NewMutexClass(reflect.TypeOf(metadataMutex{}), metadatalockNames)
}
