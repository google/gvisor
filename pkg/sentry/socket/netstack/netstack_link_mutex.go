package netstack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type netstackLinkMutex struct {
	mu sync.Mutex
}

var netstackLinkprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var netstackLinklockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type netstackLinklockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
const (
	netstackLinkLockDeststack = netstackLinklockNameIndex(0)
)
const ()

// Lock locks m.
// +checklocksignore
func (m *netstackLinkMutex) Lock() {
	locking.AddGLock(netstackLinkprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *netstackLinkMutex) NestedLock(i netstackLinklockNameIndex) {
	locking.AddGLock(netstackLinkprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *netstackLinkMutex) Unlock() {
	locking.DelGLock(netstackLinkprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *netstackLinkMutex) NestedUnlock(i netstackLinklockNameIndex) {
	locking.DelGLock(netstackLinkprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func netstackLinkinitLockNames() { netstackLinklockNames = []string{"destStack"} }

func init() {
	netstackLinkinitLockNames()
	netstackLinkprefixIndex = locking.NewMutexClass(reflect.TypeFor[netstackLinkMutex](), netstackLinklockNames)
}
