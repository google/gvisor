package mm

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type metadataMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *metadataMutex) Lock() {
	locking.AddGLock(metadataprefixIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *metadataMutex) NestedLock() {
	locking.AddGLock(metadataprefixIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *metadataMutex) Unlock() {
	locking.DelGLock(metadataprefixIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *metadataMutex) NestedUnlock() {
	locking.DelGLock(metadataprefixIndex, 1)
	m.mu.Unlock()
}

var metadataprefixIndex *locking.MutexClass

func init() {
	metadataprefixIndex = locking.NewMutexClass(reflect.TypeOf(metadataMutex{}))
}
