package mm

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type privateRefsMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *privateRefsMutex) Lock() {
	locking.AddGLock(privateRefsprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *privateRefsMutex) NestedLock() {
	locking.AddGLock(privateRefsprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *privateRefsMutex) Unlock() {
	locking.DelGLock(privateRefsprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *privateRefsMutex) NestedUnlock() {
	locking.DelGLock(privateRefsprefixIndex, 1)
	m.mu.Unlock()
}

var privateRefsprefixIndex *locking.MutexClass

func init() {
	privateRefsprefixIndex = locking.NewMutexClass(reflect.TypeOf(privateRefsMutex{}))
}
