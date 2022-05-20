package futex

import (
	"reflect"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

// Mutex is sync.Mutex with the correctness validator.
type futexBucketMutex struct {
	mu sync.Mutex
}

// Lock locks m.
// +checklocksignore
func (m *futexBucketMutex) Lock() {
	locking.AddGLock(futexBucketfutexBucketIndex, 0)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *futexBucketMutex) NestedLock() {
	locking.AddGLock(futexBucketfutexBucketIndex, 1)
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *futexBucketMutex) Unlock() {
	locking.DelGLock(futexBucketfutexBucketIndex, 0)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *futexBucketMutex) NestedUnlock() {
	locking.DelGLock(futexBucketfutexBucketIndex, 1)
	m.mu.Unlock()
}

var futexBucketfutexBucketIndex *locking.MutexClass

func init() {
	futexBucketfutexBucketIndex = locking.NewMutexClass(reflect.TypeOf(futexBucketMutex{}))
}
