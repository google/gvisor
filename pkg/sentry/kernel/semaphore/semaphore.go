// Copyright 2018 Google Inc.
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
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

const (
	valueMax = 32767 // SEMVMX

	// semaphoresMax is "maximum number of semaphores per semaphore ID" (SEMMSL).
	semaphoresMax = 32000

	// setMax is "system-wide limit on the number of semaphore sets" (SEMMNI).
	setsMax = 32000

	// semaphoresTotalMax is "system-wide limit on the number of semaphores"
	// (SEMMNS = SEMMNI*SEMMSL).
	semaphoresTotalMax = 1024000000
)

// Registry maintains a set of semaphores that can be found by key or ID.
type Registry struct {
	// userNS owning the ipc name this registry belongs to. Immutable.
	userNS *auth.UserNamespace
	// mu protects all fields below.
	mu         sync.Mutex `state:"nosave"`
	semaphores map[int32]*Set
	lastIDUsed int32
}

// Set represents a set of semaphores that can be operated atomically.
type Set struct {
	// registry owning this sem set. Immutable.
	registry *Registry

	// Id is a handle that identifies the set.
	ID int32

	// key is an user provided key that can be shared between processes.
	key int32

	// creator is the user that created the set. Immutable.
	creator fs.FileOwner

	// mu protects all fields below.
	mu         sync.Mutex `state:"nosave"`
	owner      fs.FileOwner
	perms      fs.FilePermissions
	opTime     ktime.Time
	changeTime ktime.Time
	sems       []sem

	// dead is set to true when the set is removed and can't be reached anymore.
	// All waiters must wake up and fail when set is dead.
	dead bool
}

// sem represents a single semanphore from a set.
type sem struct {
	value   int16
	waiters waiterList `state:"zerovalue"`
}

// waiter represents a caller that is waiting for the semaphore value to
// become positive or zero.
type waiter struct {
	waiterEntry

	// value represents how much resource the waiter needs to wake up.
	value int16
	ch    chan struct{}
}

// NewRegistry creates a new semaphore set registry.
func NewRegistry(userNS *auth.UserNamespace) *Registry {
	return &Registry{
		userNS:     userNS,
		semaphores: make(map[int32]*Set),
	}
}

// FindOrCreate searches for a semaphore set that matches 'key'. If not found,
// it may create a new one if requested. If private is true, key is ignored and
// a new set is always created. If create is false, it fails if a set cannot
// be found. If exclusive is true, it fails if a set with the same key already
// exists.
func (r *Registry) FindOrCreate(ctx context.Context, key, nsems int32, mode linux.FileMode, private, create, exclusive bool) (*Set, error) {
	if nsems < 0 || nsems > semaphoresMax {
		return nil, syserror.EINVAL
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if !private {
		// Look up an existing semaphore.
		if set := r.findByKey(key); set != nil {
			set.mu.Lock()
			defer set.mu.Unlock()

			// Check that caller can access semaphore set.
			creds := auth.CredentialsFromContext(ctx)
			if !set.checkPerms(creds, fs.PermsFromMode(mode)) {
				return nil, syserror.EACCES
			}

			// Validate parameters.
			if nsems > int32(set.size()) {
				return nil, syserror.EINVAL
			}
			if create && exclusive {
				return nil, syserror.EEXIST
			}
			return set, nil
		}

		if !create {
			// Semaphore not found and should not be created.
			return nil, syserror.ENOENT
		}
	}

	// Zero is only valid if an existing set is found.
	if nsems == 0 {
		return nil, syserror.EINVAL
	}

	// Apply system limits.
	if len(r.semaphores) >= setsMax {
		return nil, syserror.EINVAL
	}
	if r.totalSems() > int(semaphoresTotalMax-nsems) {
		return nil, syserror.EINVAL
	}

	// Finally create a new set.
	owner := fs.FileOwnerFromContext(ctx)
	perms := fs.FilePermsFromMode(mode)
	return r.newSet(ctx, key, owner, owner, perms, nsems)
}

// RemoveID removes set with give 'id' from the registry and marks the set as
// dead. All waiters will be awakened and fail.
func (r *Registry) RemoveID(id int32, creds *auth.Credentials) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	set := r.semaphores[id]
	if set == nil {
		return syserror.EINVAL
	}

	set.mu.Lock()
	defer set.mu.Unlock()

	// "The effective user ID of the calling process must match the creator or
	// owner of the semaphore set, or the caller must be privileged."
	if !set.checkCredentials(creds) && !set.checkCapability(creds) {
		return syserror.EACCES
	}

	delete(r.semaphores, set.ID)
	set.destroy()
	return nil
}

func (r *Registry) newSet(ctx context.Context, key int32, owner, creator fs.FileOwner, perms fs.FilePermissions, nsems int32) (*Set, error) {
	set := &Set{
		registry:   r,
		key:        key,
		owner:      owner,
		creator:    owner,
		perms:      perms,
		changeTime: ktime.NowFromContext(ctx),
		sems:       make([]sem, nsems),
	}

	// Find the next available ID.
	for id := r.lastIDUsed + 1; id != r.lastIDUsed; id++ {
		// Handle wrap around.
		if id < 0 {
			id = 0
			continue
		}
		if r.semaphores[id] == nil {
			r.lastIDUsed = id
			r.semaphores[id] = set
			set.ID = id
			return set, nil
		}
	}

	log.Warningf("Semaphore map is full, they must be leaking")
	return nil, syserror.ENOMEM
}

// FindByID looks up a set given an ID.
func (r *Registry) FindByID(id int32) *Set {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.semaphores[id]
}

func (r *Registry) findByKey(key int32) *Set {
	for _, v := range r.semaphores {
		if v.key == key {
			return v
		}
	}
	return nil
}

func (r *Registry) totalSems() int {
	totalSems := 0
	for _, v := range r.semaphores {
		totalSems += v.size()
	}
	return totalSems
}

func (s *Set) findSem(num int32) *sem {
	if num < 0 || int(num) >= s.size() {
		return nil
	}
	return &s.sems[num]
}

func (s *Set) size() int {
	return len(s.sems)
}

// Change changes some fields from the set atomically.
func (s *Set) Change(ctx context.Context, creds *auth.Credentials, owner fs.FileOwner, perms fs.FilePermissions) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// "The effective UID of the calling process must match the owner or creator
	// of the semaphore set, or the caller must be privileged."
	if !s.checkCredentials(creds) && !s.checkCapability(creds) {
		return syserror.EACCES
	}

	s.owner = owner
	s.perms = perms
	s.changeTime = ktime.NowFromContext(ctx)
	return nil
}

// SetVal overrides a semaphore value, waking up waiters as needed.
func (s *Set) SetVal(ctx context.Context, num int32, val int16, creds *auth.Credentials) error {
	if val < 0 || val > valueMax {
		return syserror.ERANGE
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// "The calling process must have alter permission on the semaphore set."
	if !s.checkPerms(creds, fs.PermMask{Write: true}) {
		return syserror.EACCES
	}

	sem := s.findSem(num)
	if sem == nil {
		return syserror.ERANGE
	}

	// TODO: Clear undo entries in all processes
	sem.value = val
	s.changeTime = ktime.NowFromContext(ctx)
	sem.wakeWaiters()
	return nil
}

// GetVal returns a semaphore value.
func (s *Set) GetVal(num int32, creds *auth.Credentials) (int16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// "The calling process must have read permission on the semaphore set."
	if !s.checkPerms(creds, fs.PermMask{Read: true}) {
		return 0, syserror.EACCES
	}

	sem := s.findSem(num)
	if sem == nil {
		return 0, syserror.ERANGE
	}
	return sem.value, nil
}

// ExecuteOps attempts to execute a list of operations to the set. It only
// succeeds when all operations can be applied. No changes are made if it fails.
//
// On failure, it may return an error (retries are hopeless) or it may return
// a channel that can be waited on before attempting again.
func (s *Set) ExecuteOps(ctx context.Context, ops []linux.Sembuf, creds *auth.Credentials) (chan struct{}, int32, error) {
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
			return nil, 0, syserror.EFBIG
		}
		if op.SemOp != 0 {
			readOnly = false
		}
	}

	if !s.checkPerms(creds, fs.PermMask{Read: readOnly, Write: !readOnly}) {
		return nil, 0, syserror.EACCES
	}

	ch, num, err := s.executeOps(ctx, ops)
	if err != nil {
		return nil, 0, err
	}
	return ch, num, nil
}

func (s *Set) executeOps(ctx context.Context, ops []linux.Sembuf) (chan struct{}, int32, error) {
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
					return nil, 0, syserror.ERANGE
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
					return nil, 0, syserror.ERANGE
				}
			}

			tmpVals[op.SemNum] += op.SemOp
		}
	}

	// All operations succeeded, apply them.
	// TODO: handle undo operations.
	for i, v := range tmpVals {
		s.sems[i].value = v
		s.sems[i].wakeWaiters()
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

func (s *Set) checkCredentials(creds *auth.Credentials) bool {
	return s.owner.UID == creds.EffectiveKUID ||
		s.owner.GID == creds.EffectiveKGID ||
		s.creator.UID == creds.EffectiveKUID ||
		s.creator.GID == creds.EffectiveKGID
}

func (s *Set) checkCapability(creds *auth.Credentials) bool {
	return creds.HasCapabilityIn(linux.CAP_IPC_OWNER, s.registry.userNS) && creds.UserNamespace.MapFromKUID(s.owner.UID).Ok()
}

func (s *Set) checkPerms(creds *auth.Credentials, reqPerms fs.PermMask) bool {
	// Are we owner, or in group, or other?
	p := s.perms.Other
	if s.owner.UID == creds.EffectiveKUID {
		p = s.perms.User
	} else if creds.InGroup(s.owner.GID) {
		p = s.perms.Group
	}

	// Are permissions satisfied without capability checks?
	if p.SupersetOf(reqPerms) {
		return true
	}

	return s.checkCapability(creds)
}

// destroy destroys the set. Caller must hold 's.mu'.
func (s *Set) destroy() {
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

// wakeWaiters goes over all waiters and checks which of them can be notified.
func (s *sem) wakeWaiters() {
	// Note that this will release all waiters waiting for 0 too.
	for w := s.waiters.Front(); w != nil; {
		if s.value < w.value {
			// Still blocked, skip it.
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
