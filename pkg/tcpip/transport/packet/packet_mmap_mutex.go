package packet

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// RWMutex is sync.RWMutex with the correctness validator.
type packetMmapRWMutex struct {
	mu sync.RWMutex
}

// lockNames is a list of user-friendly lock names.
// Populated in init.
var packetMmaplockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type packetMmaplockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *packetMmapRWMutex) Lock() {
	locking.AddGLock(packetMmapprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *packetMmapRWMutex) NestedLock(i packetMmaplockNameIndex) {
	locking.AddGLock(packetMmapprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *packetMmapRWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(packetMmapprefixIndex, -1)
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *packetMmapRWMutex) NestedUnlock(i packetMmaplockNameIndex) {
	m.mu.Unlock()
	locking.DelGLock(packetMmapprefixIndex, int(i))
}

// RLock locks m for reading.
// +checklocksignore
func (m *packetMmapRWMutex) RLock() {
	locking.AddGLock(packetMmapprefixIndex, -1)
	m.mu.RLock()
}

// RUnlock undoes a single RLock call.
// +checklocksignore
func (m *packetMmapRWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(packetMmapprefixIndex, -1)
}

// RLockBypass locks m for reading without executing the validator.
// +checklocksignore
func (m *packetMmapRWMutex) RLockBypass() {
	m.mu.RLock()
}

// RUnlockBypass undoes a single RLockBypass call.
// +checklocksignore
func (m *packetMmapRWMutex) RUnlockBypass() {
	m.mu.RUnlock()
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
// +checklocksignore
func (m *packetMmapRWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var packetMmapprefixIndex *locking.MutexClass

// DO NOT REMOVE: The following function is automatically replaced.
func packetMmapinitLockNames() {}

func init() {
	packetMmapinitLockNames()
	packetMmapprefixIndex = locking.NewMutexClass(reflect.TypeFor[packetMmapRWMutex](), packetMmaplockNames)
}
