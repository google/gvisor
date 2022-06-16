package overlay

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type mapsMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *mapsMutex) Lock() {
	locking.AddGLock(mapsprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *mapsMutex) NestedLock() {
	locking.AddGLock(mapsprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *mapsMutex) Unlock() {
	locking.DelGLock(mapsprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *mapsMutex) NestedUnlock() {
	locking.DelGLock(mapsprefixIndex, 1)
	m.mu.Unlock()
}

var mapsprefixIndex *locking.MutexClass

func init() {
	mapsprefixIndex = locking.NewMutexClass(reflect.TypeOf(mapsMutex{}))
}
