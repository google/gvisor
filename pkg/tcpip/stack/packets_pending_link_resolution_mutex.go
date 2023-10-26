package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type packetsPendingLinkResolutionMutex struct {
	mu sync.Mutex
}

var packetsPendingLinkResolutionprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var packetsPendingLinkResolutionlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type packetsPendingLinkResolutionlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *packetsPendingLinkResolutionMutex) Lock() {
	locking.AddGLock(packetsPendingLinkResolutionprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *packetsPendingLinkResolutionMutex) NestedLock(i packetsPendingLinkResolutionlockNameIndex) {
	locking.AddGLock(packetsPendingLinkResolutionprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *packetsPendingLinkResolutionMutex) Unlock() {
	locking.DelGLock(packetsPendingLinkResolutionprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *packetsPendingLinkResolutionMutex) NestedUnlock(i packetsPendingLinkResolutionlockNameIndex) {
	locking.DelGLock(packetsPendingLinkResolutionprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func packetsPendingLinkResolutioninitLockNames() {}

func init() {
	packetsPendingLinkResolutioninitLockNames()
	packetsPendingLinkResolutionprefixIndex = locking.NewMutexClass(reflect.TypeOf(packetsPendingLinkResolutionMutex{}), packetsPendingLinkResolutionlockNames)
}
