package kernel

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type signalHandlersMutex struct {
	mu sync.Mutex
}

var signalHandlersprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var signalHandlerslockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type signalHandlerslockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
const (
	signalHandlersLockTg = signalHandlerslockNameIndex(0)
)
const ()

// Lock locks m.
// +checklocksignore
func (m *signalHandlersMutex) Lock() {
	locking.AddGLock(signalHandlersprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *signalHandlersMutex) NestedLock(i signalHandlerslockNameIndex) {
	locking.AddGLock(signalHandlersprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *signalHandlersMutex) Unlock() {
	locking.DelGLock(signalHandlersprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *signalHandlersMutex) NestedUnlock(i signalHandlerslockNameIndex) {
	locking.DelGLock(signalHandlersprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func signalHandlersinitLockNames() { signalHandlerslockNames = []string{"tg"} }

func init() {
	signalHandlersinitLockNames()
	signalHandlersprefixIndex = locking.NewMutexClass(reflect.TypeOf(signalHandlersMutex{}), signalHandlerslockNames)
}
