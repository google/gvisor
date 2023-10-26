package stack

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type packetEPsRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var packetEPslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type packetEPslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *packetEPsRWMutex) Lock() {
	locking.AddGLock(packetEPsprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *packetEPsRWMutex) NestedLock(i packetEPslockNameIndex) {
	locking.AddGLock(packetEPsprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *packetEPsRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(packetEPsprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *packetEPsRWMutex) NestedUnlock(i packetEPslockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(packetEPsprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *packetEPsRWMutex) RLock() {
	locking.AddGLock(packetEPsprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *packetEPsRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(packetEPsprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *packetEPsRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *packetEPsRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *packetEPsRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var packetEPsprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func packetEPsinitLockNames() {}

func init() {
	packetEPsinitLockNames()
	packetEPsprefixIndex = locking.NewMutexClass(reflect.TypeOf(packetEPsRWMutex{}), packetEPslockNames)
}
