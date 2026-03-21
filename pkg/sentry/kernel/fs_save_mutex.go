package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type fsSaveMutex struct {
	mu sync.Mutex
}

var fsSaveprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var fsSavelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type fsSavelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *fsSaveMutex) Lock() {
	locking.AddGLock(fsSaveprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *fsSaveMutex) NestedLock(i fsSavelockNameIndex) {
	locking.AddGLock(fsSaveprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *fsSaveMutex) Unlock() {
	locking.DelGLock(fsSaveprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *fsSaveMutex) NestedUnlock(i fsSavelockNameIndex) {
	locking.DelGLock(fsSaveprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func fsSaveinitLockNames() {}

func init() {
	fsSaveinitLockNames()
	fsSaveprefixIndex = locking.NewMutexClass(reflect.TypeFor[fsSaveMutex](), fsSavelockNames)
}
