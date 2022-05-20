package auth

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type userNamespaceMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *userNamespaceMutex) Lock() {
	locking.AddGLock(userNamespaceuserNamespaceIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *userNamespaceMutex) NestedLock() {
	locking.AddGLock(userNamespaceuserNamespaceIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *userNamespaceMutex) Unlock() {
	locking.DelGLock(userNamespaceuserNamespaceIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *userNamespaceMutex) NestedUnlock() {
	locking.DelGLock(userNamespaceuserNamespaceIndex, 1)
	m.mu.Unlock()
}

var userNamespaceuserNamespaceIndex *locking.MutexClass

func init() {
	userNamespaceuserNamespaceIndex = locking.NewMutexClass(reflect.TypeOf(userNamespaceMutex{}))
}
