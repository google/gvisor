package pipe

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type pipeMutex struct {
	mu sync.Mutex
}

var pipeprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var pipelockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type pipelockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
const (
	pipeLockPipe = pipelockNameIndex(0)
)
const ()

// Lock locks m.
// +checklocksignore
func (m *pipeMutex) Lock() {
	locking.AddGLock(pipeprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pipeMutex) NestedLock(i pipelockNameIndex) {
	locking.AddGLock(pipeprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *pipeMutex) Unlock() {
	locking.DelGLock(pipeprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *pipeMutex) NestedUnlock(i pipelockNameIndex) {
	locking.DelGLock(pipeprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func pipeinitLockNames() { pipelockNames = []string{"pipe"} }

func init() {
	pipeinitLockNames()
	pipeprefixIndex = locking.NewMutexClass(reflect.TypeOf(pipeMutex{}), pipelockNames)
}
