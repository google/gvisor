package locking

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

type RWMutex struct {
	mu sync.RWMutex
}

// +checklocksignore
func (m *RWMutex) Lock() {
	locking.AddGLock(genericMarkIndex, 0)
	m.mu.Lock()
}

// +checklocksignore
func (m *RWMutex) NestedLock() {
	locking.AddGLock(genericMarkIndex, 1)
	m.mu.Lock()
}

// +checklocksignore
func (m *RWMutex) Unlock() {
	m.mu.Unlock()
	locking.DelGLock(genericMarkIndex, 0)
}

// +checklocksignore
func (m *RWMutex) NestedUnlock() {
	m.mu.Unlock()
	locking.DelGLock(genericMarkIndex, 1)
}

// +checklocksignore
func (m *RWMutex) RLock() {
	locking.AddGLock(genericMarkIndex, 0)
	m.mu.RLock()
}

// +checklocksignore
func (m *RWMutex) RUnlock() {
	m.mu.RUnlock()
	locking.DelGLock(genericMarkIndex, 0)
}

// +checklocksignore
func (m *RWMutex) DowngradeLock() {
	m.mu.DowngradeLock()
}

var genericMarkIndex *locking.MutexClass

func init() {
	genericMarkIndex = locking.NewMutexClass(reflect.TypeOf(RWMutex{}))
}
