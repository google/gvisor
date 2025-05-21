package tcp

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type hasherMutex struct {
	mu sync.Mutex
}

var hasherprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var hasherlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type hasherlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *hasherMutex) Lock() {
	locking.AddGLock(hasherprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *hasherMutex) NestedLock(i hasherlockNameIndex) {
	locking.AddGLock(hasherprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *hasherMutex) Unlock() {
	locking.DelGLock(hasherprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *hasherMutex) NestedUnlock(i hasherlockNameIndex) {
	locking.DelGLock(hasherprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func hasherinitLockNames() {}

func init() {
	hasherinitLockNames()
	hasherprefixIndex = locking.NewMutexClass(reflect.TypeOf(hasherMutex{}), hasherlockNames)
}
