package pgalloc

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type memoryFileMutex struct {
	mu sync.Mutex
}

var memoryFileprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var memoryFilelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type memoryFilelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *memoryFileMutex) Lock() {
	locking.AddGLock(memoryFileprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *memoryFileMutex) NestedLock(i memoryFilelockNameIndex) {
	locking.AddGLock(memoryFileprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *memoryFileMutex) Unlock() {
	locking.DelGLock(memoryFileprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *memoryFileMutex) NestedUnlock(i memoryFilelockNameIndex) {
	locking.DelGLock(memoryFileprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func memoryFileinitLockNames() {}

func init() {
	memoryFileinitLockNames()
	memoryFileprefixIndex = locking.NewMutexClass(reflect.TypeOf(memoryFileMutex{}), memoryFilelockNames)
}
