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

var futexBucketprefixIndex *locking.MutexClass

// lockNames is a list of user-friendly lock names.
// Populated in init.
var futexBucketlockNames []string

// lockNameIndex is used as an index passed to NestedLock and NestedUnlock,
// referring to an index within lockNames.
// Values are specified using the "consts" field of go_template_instance.
type futexBucketlockNameIndex int

// DO NOT REMOVE: The following function automatically replaced with lock index constants.
const (
	futexBucketLockB = futexBucketlockNameIndex(0)
)
const ()

// Lock locks m.
// +checklocksignore
func (m *futexBucketMutex) Lock() {
	locking.AddGLock(futexBucketprefixIndex, -1)
	m.mu.Lock()
}

// NestedLock locks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *futexBucketMutex) NestedLock(i futexBucketlockNameIndex) {
	locking.AddGLock(futexBucketprefixIndex, int(i))
	m.mu.Lock()
}

// Unlock unlocks m.
// +checklocksignore
func (m *futexBucketMutex) Unlock() {
	locking.DelGLock(futexBucketprefixIndex, -1)
	m.mu.Unlock()
}

// NestedUnlock unlocks m knowing that another lock of the same type is held.
// +checklocksignore
func (m *futexBucketMutex) NestedUnlock(i futexBucketlockNameIndex) {
	locking.DelGLock(futexBucketprefixIndex, int(i))
	m.mu.Unlock()
}

// DO NOT REMOVE: The following function is automatically replaced.
func futexBucketinitLockNames() { futexBucketlockNames = []string{"b"} }

func init() {
	futexBucketinitLockNames()
	futexBucketprefixIndex = locking.NewMutexClass(reflect.TypeOf(futexBucketMutex{}), futexBucketlockNames)
}
