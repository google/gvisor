package nvproxy

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type frontendMmapMutex struct {
	mu sync.Mutex
}

var frontendMmapprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var frontendMmaplockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type frontendMmaplockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *frontendMmapMutex) Lock() {
	locking.AddGLock(frontendMmapprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *frontendMmapMutex) NestedLock(i frontendMmaplockNameIndex) {
	locking.AddGLock(frontendMmapprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *frontendMmapMutex) Unlock() {
	locking.DelGLock(frontendMmapprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *frontendMmapMutex) NestedUnlock(i frontendMmaplockNameIndex) {
	locking.DelGLock(frontendMmapprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func frontendMmapinitLockNames() {}

func init() {
	frontendMmapinitLockNames()
	frontendMmapprefixIndex = locking.NewMutexClass(reflect.TypeOf(frontendMmapMutex{}), frontendMmaplockNames)
}
