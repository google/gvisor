package tcp

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type pendingProcessingMutex struct {
	mu sync.Mutex
}

var pendingProcessingprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var pendingProcessinglockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type pendingProcessinglockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *pendingProcessingMutex) Lock() {
	locking.AddGLock(pendingProcessingprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pendingProcessingMutex) NestedLock(i pendingProcessinglockNameIndex) {
	locking.AddGLock(pendingProcessingprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *pendingProcessingMutex) Unlock() {
	locking.DelGLock(pendingProcessingprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pendingProcessingMutex) NestedUnlock(i pendingProcessinglockNameIndex) {
	locking.DelGLock(pendingProcessingprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func pendingProcessinginitLockNames() {}

func init() {
	pendingProcessinginitLockNames()
	pendingProcessingprefixIndex = locking.NewMutexClass(reflect.TypeFor[pendingProcessingMutex](), pendingProcessinglockNames)
}
