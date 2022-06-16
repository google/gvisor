package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type dirInoCacheMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *dirInoCacheMutex) Lock() {
	locking.AddGLock(dirInoCacheprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dirInoCacheMutex) NestedLock() {
	locking.AddGLock(dirInoCacheprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *dirInoCacheMutex) Unlock() {
	locking.DelGLock(dirInoCacheprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *dirInoCacheMutex) NestedUnlock() {
	locking.DelGLock(dirInoCacheprefixIndex, 1)
	m.mu.Unlock()
}

var dirInoCacheprefixIndex *locking.MutexClass

func init() {
	dirInoCacheprefixIndex = locking.NewMutexClass(reflect.TypeOf(dirInoCacheMutex{}))
}
