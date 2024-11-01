package fdbased

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type processorMutex struct {
	mu sync.Mutex
}

var processorprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var processorlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type processorlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *processorMutex) Lock() {
	locking.AddGLock(processorprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *processorMutex) NestedLock(i processorlockNameIndex) {
	locking.AddGLock(processorprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *processorMutex) Unlock() {
	locking.DelGLock(processorprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *processorMutex) NestedUnlock(i processorlockNameIndex) {
	locking.DelGLock(processorprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func processorinitLockNames() {}

func init() {
	processorinitLockNames()
	processorprefixIndex = locking.NewMutexClass(reflect.TypeOf(processorMutex{}), processorlockNames)
}
