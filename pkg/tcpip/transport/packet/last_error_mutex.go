package packet

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type lastErrorMutex struct {
	mu sync.Mutex
}

var lastErrorprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var lastErrorlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type lastErrorlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *lastErrorMutex) Lock() {
	locking.AddGLock(lastErrorprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *lastErrorMutex) NestedLock(i lastErrorlockNameIndex) {
	locking.AddGLock(lastErrorprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *lastErrorMutex) Unlock() {
	locking.DelGLock(lastErrorprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *lastErrorMutex) NestedUnlock(i lastErrorlockNameIndex) {
	locking.DelGLock(lastErrorprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func lastErrorinitLockNames() {}

func init() {
	lastErrorinitLockNames()
	lastErrorprefixIndex = locking.NewMutexClass(reflect.TypeFor[lastErrorMutex](), lastErrorlockNames)
}
