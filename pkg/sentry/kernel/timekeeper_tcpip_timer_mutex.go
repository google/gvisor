package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type timekeeperTcpipTimerMutex struct {
	mu sync.Mutex
}

var timekeeperTcpipTimerprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var timekeeperTcpipTimerlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type timekeeperTcpipTimerlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *timekeeperTcpipTimerMutex) Lock() {
	locking.AddGLock(timekeeperTcpipTimerprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *timekeeperTcpipTimerMutex) NestedLock(i timekeeperTcpipTimerlockNameIndex) {
	locking.AddGLock(timekeeperTcpipTimerprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *timekeeperTcpipTimerMutex) Unlock() {
	locking.DelGLock(timekeeperTcpipTimerprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *timekeeperTcpipTimerMutex) NestedUnlock(i timekeeperTcpipTimerlockNameIndex) {
	locking.DelGLock(timekeeperTcpipTimerprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func timekeeperTcpipTimerinitLockNames() {}

func init() {
	timekeeperTcpipTimerinitLockNames()
	timekeeperTcpipTimerprefixIndex = locking.NewMutexClass(reflect.TypeOf(timekeeperTcpipTimerMutex{}), timekeeperTcpipTimerlockNames)
}
