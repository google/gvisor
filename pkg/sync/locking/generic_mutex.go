package locking

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

type Mutex struct {
	mu sync.Mutex
}

// +checklocksignore
func (m *Mutex) Lock() {
	locking.AddGLock(genericMarkIndex, 0)
	m.mu.Lock()
}

// +checklocksignore
func (m *Mutex) NestedLock() {
	locking.AddGLock(genericMarkIndex, 1)
	m.mu.Lock()
}

// +checklocksignore
func (m *Mutex) Unlock() {
	locking.DelGLock(genericMarkIndex, 0)
	m.mu.Unlock()
}

// +checklocksignore
func (m *Mutex) NestedUnlock() {
	locking.DelGLock(genericMarkIndex, 1)
	m.mu.Unlock()
}

var genericMarkIndex *locking.MutexClass

func init() {
	genericMarkIndex = locking.NewMutexClass(reflect.TypeOf(Mutex{}))
}
