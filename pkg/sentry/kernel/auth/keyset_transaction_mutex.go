package auth

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type keysetTransactionMutex struct {
	mu sync.Mutex
}

var keysetTransactionprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var keysetTransactionlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type keysetTransactionlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
// LOCK_NAME_INDEX_CONSTANTS
const ()

// Lock locks m.
// +checklocksignore
func (m *keysetTransactionMutex) Lock() {
	locking.AddGLock(keysetTransactionprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *keysetTransactionMutex) NestedLock(i keysetTransactionlockNameIndex) {
	locking.AddGLock(keysetTransactionprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *keysetTransactionMutex) Unlock() {
	locking.DelGLock(keysetTransactionprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *keysetTransactionMutex) NestedUnlock(i keysetTransactionlockNameIndex) {
	locking.DelGLock(keysetTransactionprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func keysetTransactioninitLockNames() {}

func init() {
	keysetTransactioninitLockNames()
	keysetTransactionprefixIndex = locking.NewMutexClass(reflect.TypeOf(keysetTransactionMutex{}), keysetTransactionlockNames)
}
