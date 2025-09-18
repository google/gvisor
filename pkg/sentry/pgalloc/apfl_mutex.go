package pgalloc

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type apflMutex struct {
	mu sync.Mutex
}

var apflprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var apfllockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type apfllockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *apflMutex) Lock() {
	locking.AddGLock(apflprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *apflMutex) NestedLock(i apfllockNameIndex) {
	locking.AddGLock(apflprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *apflMutex) Unlock() {
	locking.DelGLock(apflprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *apflMutex) NestedUnlock(i apfllockNameIndex) {
	locking.DelGLock(apflprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func apflinitLockNames() {}

func init() {
	apflinitLockNames()
	apflprefixIndex = locking.NewMutexClass(reflect.TypeFor[apflMutex](), apfllockNames)
}
