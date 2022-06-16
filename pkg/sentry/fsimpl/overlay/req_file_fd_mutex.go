package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type regularFileFDMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *regularFileFDMutex) Lock() {
	locking.AddGLock(regularFileFDprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *regularFileFDMutex) NestedLock() {
	locking.AddGLock(regularFileFDprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *regularFileFDMutex) Unlock() {
	locking.DelGLock(regularFileFDprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *regularFileFDMutex) NestedUnlock() {
	locking.DelGLock(regularFileFDprefixIndex, 1)
	m.mu.Unlock()
}

var regularFileFDprefixIndex *locking.MutexClass

func init() {
	regularFileFDprefixIndex = locking.NewMutexClass(reflect.TypeOf(regularFileFDMutex{}))
}
