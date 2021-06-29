// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package semaphore implements System V semaphores.
package semaphore

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/ipc"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

const (
	// Maximum semaphore value.
	valueMax = linux.SEMVMX

	// Maximum number of semaphore sets.
	setsMax = linux.SEMMNI

	// Maximum number of semaphores in a semaphore set.
	semsMax = linux.SEMMSL

	// Maximum number of semaphores in all semaphore sets.
	semsTotalMax = linux.SEMMNS
)

// Registry maintains a set of semaphores that can be found by key or ID.
//
// +stateify savable
type Registry struct {
	// mu protects all fields below.
	mu sync.Mutex `state:"nosave"`

	// reg defines basic fields and operations needed for all SysV registries.
	reg *ipc.Registry

	// indexes maintains a mapping between a set's index in virtual array and
	// its identifier.
	indexes map[int32]ipc.ID
}

// Set represents a set of semaphores that can be operated atomically.
//
// +stateify savable
type Set struct {
	// registry owning this sem set. Immutable.
	registry *Registry

	// mu protects all fields below.
	mu sync.Mutex `state:"nosave"`

	obj *ipc.Object

	opTime     ktime.Time
	changeTime ktime.Time

	// sems holds all semaphores in the set. The slice itself is immutable after
	// it's been set, however each 'sem' object in the slice requires 'mu' lock.
	sems []sem

	// dead is set to true when the set is removed and can't be reached anymore.
	// All waiters must wake up and fail when set is dead.
	dead bool
}

// sem represents a single semaphore from a set.
//
// +stateify savable
type sem struct {
	value   int16
	waiters waiterList `state:"zerovalue"`
	pid     int32
}

// waiter represents a caller that is waiting for the semaphore value to
// become positive or zero.
//
// +stateify savable
type waiter struct {
	waiterEntry

	// value represents how much resource the waiter needs to wake up.
	// The value is either 0 or negative.
	value int16
	ch    chan struct{}
}

// NewRegistry creates a new semaphore set registry.
func NewRegistry(userNS *auth.UserNamespace) *Registry {
	return &Registry{
		reg:     ipc.NewRegistry(userNS),
		indexes: make(map[int32]ipc.ID),
	}
}

// FindOrCreate searches for a semaphore set that matches 'key'. If not found,
// it may create a new one if requested. If private is true, key is ignored and
// a new set is always created. If create is false, it fails if a set cannot
// be found. If exclusive is true, it fails if a set with the same key already
// exists.
func (r *Registry) FindOrCreate(ctx context.Context, key ipc.Key, nsems int32, mode linux.FileMode, private, create, exclusive bool) (*Set, error) {
	if nsems < 0 || nsems > semsMax {
		return nil, linuxerr.EINVAL
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if !private {
		set, err := r.reg.Find(ctx, key, mode, create, exclusive)
		if err != nil {
			return nil, err
		}

		// Validate semaphore-specific parameters.
		if set != nil {
			set := set.(*Set)
			if nsems > int32(set.Size()) {
				return nil, linuxerr.EINVAL
			}
			return set, nil
		}
	}

	// Zero is only valid if an existing set is found.
	if nsems == 0 {
		return nil, linuxerr.EINVAL
	}

	// Apply system limits.
	//
	// Map reg.objects and map indexes in a registry are of the same size,
	// check map reg.objects only here for the system limit.
	if r.reg.ObjectCount() >= setsMax {
		return nil, syserror.ENOSPC
	}
	if r.totalSems() > int(semsTotalMax-nsems) {
		return nil, syserror.ENOSPC
	}

	// Finally create a new set.
	return r.newSetLocked(ctx, key, fs.FileOwnerFromContext(ctx), fs.FilePermsFromMode(mode), nsems)
}

// IPCInfo returns information about system-wide semaphore limits and parameters.
func (r *Registry) IPCInfo() *linux.SemInfo {
	return &linux.SemInfo{
		SemMap: linux.SEMMAP,
		SemMni: linux.SEMMNI,
		SemMns: linux.SEMMNS,
		SemMnu: linux.SEMMNU,
		SemMsl: linux.SEMMSL,
		SemOpm: linux.SEMOPM,
		SemUme: linux.SEMUME,
		SemUsz: linux.SEMUSZ,
		SemVmx: linux.SEMVMX,
		SemAem: linux.SEMAEM,
	}
}

// SemInfo returns a seminfo structure containing the same information as
// for IPC_INFO, except that SemUsz field returns the number of existing
// semaphore sets, and SemAem field returns the number of existing semaphores.
func (r *Registry) SemInfo() *linux.SemInfo {
	r.mu.Lock()
	defer r.mu.Unlock()

	info := r.IPCInfo()
	info.SemUsz = uint32(r.reg.ObjectCount())
	info.SemAem = uint32(r.totalSems())

	return info
}

// HighestIndex returns the index of the highest used entry in
// the kernel's array.
func (r *Registry) HighestIndex() int32 {
	r.mu.Lock()
	defer r.mu.Unlock()

	// By default, highest used index is 0 even though
	// there is no semaphore set.
	var highestIndex int32
	for index := range r.indexes {
		if index > highestIndex {
			highestIndex = index
		}
	}
	return highestIndex
}

// Remove removes set with give 'id' from the registry and marks the set as
// dead. All waiters will be awakened and fail.
func (r *Registry) Remove(id ipc.ID, creds *auth.Credentials) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	index, found := r.findIndexByID(id)
	if !found {
		return linuxerr.EINVAL
	}
	delete(r.indexes, index)

	r.reg.Remove(id, creds)

	return nil
}

// newSetLocked creates a new Set using given fields. An error is returned if there
// are no more available identifiers.
//
// Precondition: r.mu must be held.
func (r *Registry) newSetLocked(ctx context.Context, key ipc.Key, creator fs.FileOwner, perms fs.FilePermissions, nsems int32) (*Set, error) {
	set := &Set{
		registry:   r,
		obj:        ipc.NewObject(r.reg.UserNS, ipc.Key(key), creator, creator, perms),
		changeTime: ktime.NowFromContext(ctx),
		sems:       make([]sem, nsems),
	}

	err := r.reg.Register(set)
	if err != nil {
		return nil, err
	}

	index, found := r.findFirstAvailableIndex()
	if !found {
		// See linux, ipc/sem.c:newary().
		return nil, linuxerr.ENOSPC
	}
	r.indexes[index] = set.obj.ID

	return set, nil
}

// FindByID looks up a set given an ID.
func (r *Registry) FindByID(id ipc.ID) *Set {
	r.mu.Lock()
	defer r.mu.Unlock()
	mech := r.reg.FindByID(id)
	if mech == nil {
		return nil
	}
	return mech.(*Set)
}

// FindByIndex looks up a set given an index.
func (r *Registry) FindByIndex(index int32) *Set {
	r.mu.Lock()
	defer r.mu.Unlock()

	id, present := r.indexes[index]
	if !present {
		return nil
	}
	return r.reg.FindByID(id).(*Set)
}

func (r *Registry) findIndexByID(id ipc.ID) (int32, bool) {
	for k, v := range r.indexes {
		if v == id {
			return k, true
		}
	}
	return 0, false
}

func (r *Registry) findFirstAvailableIndex() (int32, bool) {
	for index := int32(0); index < setsMax; index++ {
		if _, present := r.indexes[index]; !present {
			return index, true
		}
	}
	return 0, false
}

func (r *Registry) totalSems() int {
	totalSems := 0
	r.reg.ForAllObjects(
		func(o ipc.Mechanism) {
			totalSems += o.(*Set).Size()
		},
	)
	return totalSems
}

// ID returns semaphore's ID.
func (s *Set) ID() ipc.ID {
	return s.obj.ID
}

// Object implements ipc.Mechanism.Object.
func (s *Set) Object() *ipc.Object {
	return s.obj
}

// Lock implements ipc.Mechanism.Lock.
func (s *Set) Lock() {
	s.mu.Lock()
}

// Unlock implements ipc.mechanism.Unlock.
//
// +checklocksignore
func (s *Set) Unlock() {
	s.mu.Unlock()
}

func (s *Set) findSem(num int32) *sem {
	if num < 0 || int(num) >= s.Size() {
		return nil
	}
	return &s.sems[num]
}

// Size returns the number of semaphores in the set. Size is immutable.
func (s *Set) Size() int {
	return len(s.sems)
}

// Set modifies attributes for a semaphore set. See semctl(IPC_SET).
func (s *Set) Set(ctx context.Context, ds *linux.SemidDS) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.obj.Set(ctx, &ds.SemPerm); err != nil {
		return err
	}

	s.changeTime = ktime.NowFromContext(ctx)
	return nil
}

// GetStat extracts semid_ds information from the set.
func (s *Set) GetStat(creds *auth.Credentials) (*linux.SemidDS, error) {
	// "The calling process must have read permission on the semaphore set."
	return s.semStat(creds, fs.PermMask{Read: true})
}

// GetStatAny extracts semid_ds information from the set without requiring read access.
func (s *Set) GetStatAny(creds *auth.Credentials) (*linux.SemidDS, error) {
	return s.semStat(creds, fs.PermMask{})
}

func (s *Set) semStat(creds *auth.Credentials, permMask fs.PermMask) (*linux.SemidDS, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.obj.CheckPermissions(creds, permMask) {
		return nil, linuxerr.EACCES
	}

	return &linux.SemidDS{
		SemPerm: linux.IPCPerm{
			Key:  uint32(s.obj.Key),
			UID:  uint32(creds.UserNamespace.MapFromKUID(s.obj.Owner.UID)),
			GID:  uint32(creds.UserNamespace.MapFromKGID(s.obj.Owner.GID)),
			CUID: uint32(creds.UserNamespace.MapFromKUID(s.obj.Creator.UID)),
			CGID: uint32(creds.UserNamespace.MapFromKGID(s.obj.Creator.GID)),
			Mode: uint16(s.obj.Perms.LinuxMode()),
			Seq:  0, // IPC sequence not supported.
		},
		SemOTime: s.opTime.TimeT(),
		SemCTime: s.changeTime.TimeT(),
		SemNSems: uint64(s.Size()),
	}, nil
}

// SetVal overrides a semaphore value, waking up waiters as needed.
func (s *Set) SetVal(ctx context.Context, num int32, val int16, creds *auth.Credentials, pid int32) error {
	if val < 0 || val > valueMax {
		return linuxerr.ERANGE
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// "The calling process must have alter permission on the semaphore set."
	if !s.obj.CheckPermissions(creds, fs.PermMask{Write: true}) {
		return linuxerr.EACCES
	}

	sem := s.findSem(num)
	if sem == nil {
		return linuxerr.ERANGE
	}

	// TODO(gvisor.dev/issue/137): Clear undo entries in all processes.
	sem.value = val
	sem.pid = pid
	s.changeTime = ktime.NowFromContext(ctx)
	sem.wakeWaiters()
	return nil
}

// SetValAll overrides all semaphores values, waking up waiters as needed. It also
// sets semaphore's PID which was fixed in Linux 4.6.
//
// 'len(vals)' must be equal to 's.Size()'.
func (s *Set) SetValAll(ctx context.Context, vals []uint16, creds *auth.Credentials, pid int32) error {
	if len(vals) != s.Size() {
		panic(fmt.Sprintf("vals length (%d) different that Set.Size() (%d)", len(vals), s.Size()))
	}

	for _, val := range vals {
		if val > valueMax {
			return linuxerr.ERANGE
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// "The calling process must have alter permission on the semaphore set."
	if !s.obj.CheckPermissions(creds, fs.PermMask{Write: true}) {
		return linuxerr.EACCES
	}

	for i, val := range vals {
		sem := &s.sems[i]

		// TODO(gvisor.dev/issue/137): Clear undo entries in all processes.
		sem.value = int16(val)
		sem.pid = pid
		sem.wakeWaiters()
	}
	s.changeTime = ktime.NowFromContext(ctx)
	return nil
}

// GetVal returns a semaphore value.
func (s *Set) GetVal(num int32, creds *auth.Credentials) (int16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// "The calling process must have read permission on the semaphore set."
	if !s.obj.CheckPermissions(creds, fs.PermMask{Read: true}) {
		return 0, linuxerr.EACCES
	}

	sem := s.findSem(num)
	if sem == nil {
		return 0, linuxerr.ERANGE
	}
	return sem.value, nil
}

// GetValAll returns value for all semaphores.
func (s *Set) GetValAll(creds *auth.Credentials) ([]uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// "The calling process must have read permission on the semaphore set."
	if !s.obj.CheckPermissions(creds, fs.PermMask{Read: true}) {
		return nil, linuxerr.EACCES
	}

	vals := make([]uint16, s.Size())
	for i, sem := range s.sems {
		vals[i] = uint16(sem.value)
	}
	return vals, nil
}

// GetPID returns the PID set when performing operations in the semaphore.
func (s *Set) GetPID(num int32, creds *auth.Credentials) (int32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// "The calling process must have read permission on the semaphore set."
	if !s.obj.CheckPermissions(creds, fs.PermMask{Read: true}) {
		return 0, linuxerr.EACCES
	}

	sem := s.findSem(num)
	if sem == nil {
		return 0, linuxerr.ERANGE
	}
	return sem.pid, nil
}

func (s *Set) countWaiters(num int32, creds *auth.Credentials, pred func(w *waiter) bool) (uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// The calling process must have read permission on the semaphore set.
	if !s.obj.CheckPermissions(creds, fs.PermMask{Read: true}) {
		return 0, linuxerr.EACCES
	}

	sem := s.findSem(num)
	if sem == nil {
		return 0, linuxerr.ERANGE
	}
	var cnt uint16
	for w := sem.waiters.Front(); w != nil; w = w.Next() {
		if pred(w) {
			cnt++
		}
	}
	return cnt, nil
}

// CountZeroWaiters returns number of waiters waiting for the sem's value to increase.
func (s *Set) CountZeroWaiters(num int32, creds *auth.Credentials) (uint16, error) {
	return s.countWaiters(num, creds, func(w *waiter) bool {
		return w.value == 0
	})
}

// CountNegativeWaiters returns number of waiters waiting for the sem to go to zero.
func (s *Set) CountNegativeWaiters(num int32, creds *auth.Credentials) (uint16, error) {
	return s.countWaiters(num, creds, func(w *waiter) bool {
		return w.value < 0
	})
}

// ExecuteOps attempts to execute a list of operations to the set. It only
// succeeds when all operations can be applied. No changes are made if it fails.
//
// On failure, it may return an error (retries are hopeless) or it may return
// a channel that can be waited on before attempting again.
func (s *Set) ExecuteOps(ctx context.Context, ops []linux.Sembuf, creds *auth.Credentials, pid int32) (chan struct{}, int32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Did it race with a removal operation?
	if s.dead {
		return nil, 0, syserror.EIDRM
	}

	// Validate the operations.
	readOnly := true
	for _, op := range ops {
		if s.findSem(int32(op.SemNum)) == nil {
			return nil, 0, linuxerr.EFBIG
		}
		if op.SemOp != 0 {
			readOnly = false
		}
	}

	if !s.obj.CheckPermissions(creds, fs.PermMask{Read: readOnly, Write: !readOnly}) {
		return nil, 0, linuxerr.EACCES
	}

	ch, num, err := s.executeOps(ctx, ops, pid)
	if err != nil {
		return nil, 0, err
	}
	return ch, num, nil
}

func (s *Set) executeOps(ctx context.Context, ops []linux.Sembuf, pid int32) (chan struct{}, int32, error) {
	// Changes to semaphores go to this slice temporarily until they all succeed.
	tmpVals := make([]int16, len(s.sems))
	for i := range s.sems {
		tmpVals[i] = s.sems[i].value
	}

	for _, op := range ops {
		sem := &s.sems[op.SemNum]
		if op.SemOp == 0 {
			// Handle 'wait for zero' operation.
			if tmpVals[op.SemNum] != 0 {
				// Semaphore isn't 0, must wait.
				if op.SemFlg&linux.IPC_NOWAIT != 0 {
					return nil, 0, syserror.ErrWouldBlock
				}

				w := newWaiter(op.SemOp)
				sem.waiters.PushBack(w)
				return w.ch, int32(op.SemNum), nil
			}
		} else {
			if op.SemOp < 0 {
				// Handle 'wait' operation.
				if -op.SemOp > valueMax {
					return nil, 0, linuxerr.ERANGE
				}
				if -op.SemOp > tmpVals[op.SemNum] {
					// Not enough resources, must wait.
					if op.SemFlg&linux.IPC_NOWAIT != 0 {
						return nil, 0, syserror.ErrWouldBlock
					}

					w := newWaiter(op.SemOp)
					sem.waiters.PushBack(w)
					return w.ch, int32(op.SemNum), nil
				}
			} else {
				// op.SemOp > 0: Handle 'signal' operation.
				if tmpVals[op.SemNum] > valueMax-op.SemOp {
					return nil, 0, linuxerr.ERANGE
				}
			}

			tmpVals[op.SemNum] += op.SemOp
		}
	}

	// All operations succeeded, apply them.
	// TODO(gvisor.dev/issue/137): handle undo operations.
	for i, v := range tmpVals {
		s.sems[i].value = v
		s.sems[i].wakeWaiters()
		s.sems[i].pid = pid
	}
	s.opTime = ktime.NowFromContext(ctx)
	return nil, 0, nil
}

// AbortWait notifies that a waiter is giving up and will not wait on the
// channel anymore.
func (s *Set) AbortWait(num int32, ch chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sem := &s.sems[num]
	for w := sem.waiters.Front(); w != nil; w = w.Next() {
		if w.ch == ch {
			sem.waiters.Remove(w)
			return
		}
	}
	// Waiter may not be found in case it raced with wakeWaiters().
}

// Destroy implements ipc.Mechanism.Destroy.
//
// Preconditions: Caller must hold 's.mu'.
func (s *Set) Destroy() {
	// Notify all waiters. They will fail on the next attempt to execute
	// operations and return error.
	s.dead = true
	for _, s := range s.sems {
		for w := s.waiters.Front(); w != nil; w = w.Next() {
			w.ch <- struct{}{}
		}
		s.waiters.Reset()
	}
}

func abs(val int16) int16 {
	if val < 0 {
		return -val
	}
	return val
}

// wakeWaiters goes over all waiters and checks which of them can be notified.
func (s *sem) wakeWaiters() {
	// Note that this will release all waiters waiting for 0 too.
	for w := s.waiters.Front(); w != nil; {
		if s.value < abs(w.value) {
			// Still blocked, skip it.
			w = w.Next()
			continue
		}
		w.ch <- struct{}{}
		old := w
		w = w.Next()
		s.waiters.Remove(old)
	}
}

func newWaiter(val int16) *waiter {
	return &waiter{
		value: val,
		ch:    make(chan struct{}, 1),
	}
}
