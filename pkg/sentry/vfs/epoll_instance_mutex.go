package vfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type epollReadyInstanceMutex struct {
	mu sync.Mutex
}

var epollReadyInstanceprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var epollReadyInstancelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type epollReadyInstancelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *epollReadyInstanceMutex) Lock() {
	locking.AddGLock(epollReadyInstanceprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epollReadyInstanceMutex) NestedLock(i epollReadyInstancelockNameIndex) {
	locking.AddGLock(epollReadyInstanceprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *epollReadyInstanceMutex) Unlock() {
	locking.DelGLock(epollReadyInstanceprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epollReadyInstanceMutex) NestedUnlock(i epollReadyInstancelockNameIndex) {
	locking.DelGLock(epollReadyInstanceprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func epollReadyInstanceinitLockNames() {}

func init() {
	epollReadyInstanceinitLockNames()
	epollReadyInstanceprefixIndex = locking.NewMutexClass(reflect.TypeOf(epollReadyInstanceMutex{}), epollReadyInstancelockNames)
}
