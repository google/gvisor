package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type directoryFDMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *directoryFDMutex) Lock() {
	locking.AddGLock(directoryFDprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *directoryFDMutex) NestedLock() {
	locking.AddGLock(directoryFDprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *directoryFDMutex) Unlock() {
	locking.DelGLock(directoryFDprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *directoryFDMutex) NestedUnlock() {
	locking.DelGLock(directoryFDprefixIndex, 1)
	m.mu.Unlock()
}

var directoryFDprefixIndex *locking.MutexClass

func init() {
	directoryFDprefixIndex = locking.NewMutexClass(reflect.TypeOf(directoryFDMutex{}))
}
