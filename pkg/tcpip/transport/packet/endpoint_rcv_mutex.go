package packet

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type rcvMutex struct {
	mu sync.Mutex
}

var rcvprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var rcvlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type rcvlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *rcvMutex) Lock() {
	locking.AddGLock(rcvprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *rcvMutex) NestedLock(i rcvlockNameIndex) {
	locking.AddGLock(rcvprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *rcvMutex) Unlock() {
	locking.DelGLock(rcvprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *rcvMutex) NestedUnlock(i rcvlockNameIndex) {
	locking.DelGLock(rcvprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func rcvinitLockNames() {}

func init() {
	rcvinitLockNames()
	rcvprefixIndex = locking.NewMutexClass(reflect.TypeFor[rcvMutex](), rcvlockNames)
}
