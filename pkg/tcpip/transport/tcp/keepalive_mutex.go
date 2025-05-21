package tcp

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type keepaliveMutex struct {
	mu sync.Mutex
}

var keepaliveprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var keepalivelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type keepalivelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *keepaliveMutex) Lock() {
	locking.AddGLock(keepaliveprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *keepaliveMutex) NestedLock(i keepalivelockNameIndex) {
	locking.AddGLock(keepaliveprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *keepaliveMutex) Unlock() {
	locking.DelGLock(keepaliveprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *keepaliveMutex) NestedUnlock(i keepalivelockNameIndex) {
	locking.DelGLock(keepaliveprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func keepaliveinitLockNames() {}

func init() {
	keepaliveinitLockNames()
	keepaliveprefixIndex = locking.NewMutexClass(reflect.TypeOf(keepaliveMutex{}), keepalivelockNames)
}
