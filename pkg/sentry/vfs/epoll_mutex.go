package vfs

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type epollMutex struct {
	mu sync.Mutex
}

var epollprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var epolllockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type epolllockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *epollMutex) Lock() {
	locking.AddGLock(epollprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epollMutex) NestedLock(i epolllockNameIndex) {
	locking.AddGLock(epollprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *epollMutex) Unlock() {
	locking.DelGLock(epollprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *epollMutex) NestedUnlock(i epolllockNameIndex) {
	locking.DelGLock(epollprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func epollinitLockNames() {}

func init() {
	epollinitLockNames()
	epollprefixIndex = locking.NewMutexClass(reflect.TypeOf(epollMutex{}), epolllockNames)
}
