package tcp

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type rttMutex struct {
	mu sync.Mutex
}

var rttprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var rttlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type rttlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *rttMutex) Lock() {
	locking.AddGLock(rttprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *rttMutex) NestedLock(i rttlockNameIndex) {
	locking.AddGLock(rttprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *rttMutex) Unlock() {
	locking.DelGLock(rttprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *rttMutex) NestedUnlock(i rttlockNameIndex) {
	locking.DelGLock(rttprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func rttinitLockNames() {}

func init() {
	rttinitLockNames()
	rttprefixIndex = locking.NewMutexClass(reflect.TypeFor[rttMutex](), rttlockNames)
}
