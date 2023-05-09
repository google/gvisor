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

// Package shm implements sysv shared memory segments.
//
// Known missing features:
//
//   - SHM_LOCK/SHM_UNLOCK are no-ops. The sentry currently doesn't implement
//     memory locking in general.
//
//   - SHM_HUGETLB and related flags for shmget(2) are ignored. There's no easy
//     way to implement hugetlb support on a per-map basis, and it has no impact
//     on correctness.
//
//   - SHM_NORESERVE for shmget(2) is ignored, the sentry doesn't implement swap
//     so it's meaningless to reserve space for swap.
//
//   - No per-process segment size enforcement. This feature probably isn't used
//     much anyways, since Linux sets the per-process limits to the system-wide
//     limits by default.
//
// Lock ordering: mm.mappingMu -> shm registry lock -> shm lock
package shm

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/ipc"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// Registry tracks all shared memory segments in an IPC namespace. The registry
// provides the mechanisms for creating and finding segments, and reporting
// global shm parameters.
//
// +stateify savable
type Registry struct {
	// userNS owns the IPC namespace this registry belong to. Immutable.
	userNS *auth.UserNamespace

	// mu protects all fields below.
	mu sync.Mutex `state:"nosave"`

	// reg defines basic fields and operations needed for all SysV registries.
	//
	// Withing reg, there are two maps, Objects and KeysToIDs.
	//
	// reg.objects holds all referenced segments, which are removed on the last
	// DecRef. Thus, it cannot itself hold a reference on the Shm.
	//
	// Since removal only occurs after the last (unlocked) DecRef, there
	// exists a short window during which a Shm still exists in Shm, but is
	// unreferenced. Users must use TryIncRef to determine if the Shm is
	// still valid.
	//
	// keysToIDs maps segment keys to IDs.
	//
	// Shms in keysToIDs are guaranteed to be referenced, as they are
	// removed by disassociateKey before the last DecRef.
	reg *ipc.Registry

	// Sum of the sizes of all existing segments rounded up to page size, in
	// units of page size.
	totalPages uint64
}

// NewRegistry creates a new shm registry.
func NewRegistry(userNS *auth.UserNamespace) *Registry {
	return &Registry{
		userNS: userNS,
		reg:    ipc.NewRegistry(userNS),
	}
}

// FindByID looks up a segment given an ID.
//
// FindByID returns a reference on Shm.
func (r *Registry) FindByID(id ipc.ID) *Shm {
	r.mu.Lock()
	defer r.mu.Unlock()
	mech := r.reg.FindByID(id)
	if mech == nil {
		return nil
	}
	s := mech.(*Shm)

	// Take a reference on s. If TryIncRef fails, s has reached the last
	// DecRef, but hasn't quite been removed from r.reg.objects yet.
	if s != nil && s.TryIncRef() {
		return s
	}
	return nil
}

// dissociateKey removes the association between a segment and its key,
// preventing it from being discovered in the registry. This doesn't necessarily
// mean the segment is about to be destroyed. This is analogous to unlinking a
// file; the segment can still be used by a process already referencing it, but
// cannot be discovered by a new process.
func (r *Registry) dissociateKey(s *Shm) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.obj.Key != linux.IPC_PRIVATE {
		r.reg.DissociateKey(s.obj.Key)
		s.obj.Key = linux.IPC_PRIVATE
	}
}

// FindOrCreate looks up or creates a segment in the registry. It's functionally
// analogous to open(2).
//
// FindOrCreate returns a reference on Shm.
func (r *Registry) FindOrCreate(ctx context.Context, pid int32, key ipc.Key, size uint64, mode linux.FileMode, private, create, exclusive bool) (*Shm, error) {
	if (create || private) && (size < linux.SHMMIN || size > linux.SHMMAX) {
		// "A new segment was to be created and size is less than SHMMIN or
		// greater than SHMMAX." - man shmget(2)
		//
		// Note that 'private' always implies the creation of a new segment
		// whether IPC_CREAT is specified or not.
		return nil, linuxerr.EINVAL
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.reg.ObjectCount() >= linux.SHMMNI {
		// "All possible shared memory IDs have been taken (SHMMNI) ..."
		//   - man shmget(2)
		return nil, linuxerr.ENOSPC
	}

	if !private {
		shm, err := r.reg.Find(ctx, key, mode, create, exclusive)
		if err != nil {
			return nil, err
		}

		// Validate shm-specific parameters.
		if shm != nil {
			shm := shm.(*Shm)
			if size > shm.size {
				// "A segment for the given key exists, but size is greater than
				// the size of that segment." - man shmget(2)
				return nil, linuxerr.EINVAL
			}
			shm.IncRef()
			return shm, nil
		}
	}

	var sizeAligned uint64
	if val, ok := hostarch.Addr(size).RoundUp(); ok {
		sizeAligned = uint64(val)
	} else {
		return nil, linuxerr.EINVAL
	}

	if numPages := sizeAligned / hostarch.PageSize; r.totalPages+numPages > linux.SHMALL {
		// "... allocating a segment of the requested size would cause the
		// system to exceed the system-wide limit on shared memory (SHMALL)."
		//   - man shmget(2)
		return nil, linuxerr.ENOSPC
	}

	// Need to create a new segment.
	s, err := r.newShmLocked(ctx, pid, key, auth.CredentialsFromContext(ctx), mode, size)
	if err != nil {
		return nil, err
	}
	// The initial reference is held by s itself. Take another to return to
	// the caller.
	s.IncRef()
	return s, nil
}

// newShmLocked creates a new segment in the registry.
//
// Precondition: Caller must hold r.mu.
func (r *Registry) newShmLocked(ctx context.Context, pid int32, key ipc.Key, creator *auth.Credentials, mode linux.FileMode, size uint64) (*Shm, error) {
	mfp := pgalloc.MemoryFileProviderFromContext(ctx)
	if mfp == nil {
		panic(fmt.Sprintf("context.Context %T lacks non-nil value for key %T", ctx, pgalloc.CtxMemoryFileProvider))
	}

	effectiveSize := uint64(hostarch.Addr(size).MustRoundUp())
	fr, err := mfp.MemoryFile().Allocate(effectiveSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		return nil, err
	}

	shm := &Shm{
		mfp:           mfp,
		registry:      r,
		size:          size,
		effectiveSize: effectiveSize,
		obj:           ipc.NewObject(r.reg.UserNS, ipc.Key(key), creator, creator, mode),
		fr:            fr,
		creatorPID:    pid,
		changeTime:    ktime.NowFromContext(ctx),
	}
	shm.InitRefs()

	if err := r.reg.Register(shm); err != nil {
		return nil, err
	}
	r.totalPages += effectiveSize / hostarch.PageSize

	return shm, nil
}

// IPCInfo reports global parameters for sysv shared memory segments on this
// system. See shmctl(IPC_INFO).
func (r *Registry) IPCInfo() *linux.ShmParams {
	return &linux.ShmParams{
		ShmMax: linux.SHMMAX,
		ShmMin: linux.SHMMIN,
		ShmMni: linux.SHMMNI,
		ShmSeg: linux.SHMSEG,
		ShmAll: linux.SHMALL,
	}
}

// ShmInfo reports linux-specific global parameters for sysv shared memory
// segments on this system. See shmctl(SHM_INFO).
func (r *Registry) ShmInfo() *linux.ShmInfo {
	r.mu.Lock()
	defer r.mu.Unlock()

	return &linux.ShmInfo{
		UsedIDs: int32(r.reg.LastIDUsed()),
		ShmTot:  r.totalPages,
		ShmRss:  r.totalPages, // We could probably get a better estimate from memory accounting.
		ShmSwp:  0,            // No reclaim at the moment.
	}
}

// remove deletes a segment from this registry, deaccounting the memory used by
// the segment.
//
// Precondition: Must follow a call to r.dissociateKey(s).
func (r *Registry) remove(s *Shm) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.obj.Key != linux.IPC_PRIVATE {
		panic(fmt.Sprintf("Attempted to remove %s from the registry whose key is still associated", s.debugLocked()))
	}

	r.reg.DissociateID(s.obj.ID)
	r.totalPages -= s.effectiveSize / hostarch.PageSize
}

// Release drops the self-reference of each active shm segment in the registry.
// It is called when the kernel.IPCNamespace containing r is being destroyed.
func (r *Registry) Release(ctx context.Context) {
	// Because Shm.DecRef() may acquire the same locks, collect the segments to
	// release first. Note that this should not race with any updates to r, since
	// the IPC namespace containing it has no more references.
	toRelease := make([]*Shm, 0)
	r.mu.Lock()
	r.reg.ForAllObjects(
		func(o ipc.Mechanism) {
			s := o.(*Shm)
			s.mu.Lock()
			if !s.pendingDestruction {
				toRelease = append(toRelease, s)
			}
			s.mu.Unlock()
		},
	)
	r.mu.Unlock()

	for _, s := range toRelease {
		r.dissociateKey(s)
		s.DecRef(ctx)
	}
}

// Shm represents a single shared memory segment.
//
// Shm segments are backed directly by an allocation from platform memory.
// Segments are always mapped as a whole, greatly simplifying how mappings are
// tracked. However note that mremap and munmap calls may cause the vma for a
// segment to become fragmented; which requires special care when unmapping a
// segment. See mm/shm.go.
//
// Segments persist until they are explicitly marked for destruction via
// MarkDestroyed().
//
// Shm implements memmap.Mappable and memmap.MappingIdentity.
//
// +stateify savable
type Shm struct {
	// ShmRefs tracks the number of references to this segment.
	//
	// A segment holds a reference to itself until it is marked for
	// destruction.
	//
	// In addition to direct users, the MemoryManager will hold references
	// via MappingIdentity.
	ShmRefs

	mfp pgalloc.MemoryFileProvider

	// registry points to the shm registry containing this segment. Immutable.
	registry *Registry

	// size is the requested size of the segment at creation, in
	// bytes. Immutable.
	size uint64

	// effectiveSize of the segment, rounding up to the next page
	// boundary. Immutable.
	//
	// Invariant: effectiveSize must be a multiple of hostarch.PageSize.
	effectiveSize uint64

	// fr is the offset into mfp.MemoryFile() that backs this contents of this
	// segment. Immutable.
	fr memmap.FileRange

	// mu protects all fields below.
	mu sync.Mutex `state:"nosave"`

	obj *ipc.Object

	// attachTime is updated on every successful shmat.
	attachTime ktime.Time
	// detachTime is updated on every successful shmdt.
	detachTime ktime.Time
	// changeTime is updated on every successful changes to the segment via
	// shmctl(IPC_SET).
	changeTime ktime.Time

	// creatorPID is the PID of the process that created the segment.
	creatorPID int32
	// lastAttachDetachPID is the pid of the process that issued the last shmat
	// or shmdt syscall.
	lastAttachDetachPID int32

	// pendingDestruction indicates the segment was marked as destroyed through
	// shmctl(IPC_RMID). When marked as destroyed, the segment will not be found
	// in the registry and can no longer be attached. When the last user
	// detaches from the segment, it is destroyed.
	pendingDestruction bool
}

// ID returns object's ID.
func (s *Shm) ID() ipc.ID {
	return s.obj.ID
}

// Object implements ipc.Mechanism.Object.
func (s *Shm) Object() *ipc.Object {
	return s.obj
}

// Destroy implements ipc.Mechanism.Destroy. No work is performed on shm.Destroy
// because a different removal mechanism is used in shm. See Shm.MarkDestroyed.
func (s *Shm) Destroy() {
}

// Lock implements ipc.Mechanism.Lock.
func (s *Shm) Lock() {
	s.mu.Lock()
}

// Unlock implements ipc.mechanism.Unlock.
//
// +checklocksignore
func (s *Shm) Unlock() {
	s.mu.Unlock()
}

// Precondition: Caller must hold s.mu.
func (s *Shm) debugLocked() string {
	return fmt.Sprintf("Shm{id: %d, key: %d, size: %d bytes, refs: %d, destroyed: %v}",
		s.obj.ID, s.obj.Key, s.size, s.ReadRefs(), s.pendingDestruction)
}

// MappedName implements memmap.MappingIdentity.MappedName.
func (s *Shm) MappedName(ctx context.Context) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("SYSV%08d", s.obj.Key)
}

// DeviceID implements memmap.MappingIdentity.DeviceID.
func (s *Shm) DeviceID() uint64 {
	return shmDevice.DeviceID()
}

// InodeID implements memmap.MappingIdentity.InodeID.
func (s *Shm) InodeID() uint64 {
	// "shmid gets reported as "inode#" in /proc/pid/maps. proc-ps tools use
	// this. Changing this will break them." -- Linux, ipc/shm.c:newseg()
	return uint64(s.obj.ID)
}

// DecRef drops a reference on s.
//
// Precondition: Caller must not hold s.mu.
func (s *Shm) DecRef(ctx context.Context) {
	s.ShmRefs.DecRef(func() {
		s.mfp.MemoryFile().DecRef(s.fr)
		s.registry.remove(s)
	})
}

// Msync implements memmap.MappingIdentity.Msync. Msync is a no-op for shm
// segments.
func (s *Shm) Msync(context.Context, memmap.MappableRange) error {
	return nil
}

// AddMapping implements memmap.Mappable.AddMapping.
func (s *Shm) AddMapping(ctx context.Context, _ memmap.MappingSpace, _ hostarch.AddrRange, _ uint64, _ bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attachTime = ktime.NowFromContext(ctx)
	if pid, ok := auth.ThreadGroupIDFromContext(ctx); ok {
		s.lastAttachDetachPID = pid
	} else {
		// AddMapping is called during a syscall, so ctx should always be a task
		// context.
		log.Warningf("Adding mapping to %s but couldn't get the current pid; not updating the last attach pid", s.debugLocked())
	}
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (s *Shm) RemoveMapping(ctx context.Context, _ memmap.MappingSpace, _ hostarch.AddrRange, _ uint64, _ bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// RemoveMapping may be called during task exit, when ctx
	// is context.Background. Gracefully handle missing clocks. Failing to
	// update the detach time in these cases is ok, since no one can observe the
	// omission.
	if clock := ktime.RealtimeClockFromContext(ctx); clock != nil {
		s.detachTime = clock.Now()
	}

	// If called from a non-task context we also won't have a threadgroup
	// id. Silently skip updating the lastAttachDetachPid in that case.
	if pid, ok := auth.ThreadGroupIDFromContext(ctx); ok {
		s.lastAttachDetachPID = pid
	} else {
		log.Debugf("Couldn't obtain pid when removing mapping to %s, not updating the last detach pid.", s.debugLocked())
	}
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (*Shm) CopyMapping(context.Context, memmap.MappingSpace, hostarch.AddrRange, hostarch.AddrRange, uint64, bool) error {
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (s *Shm) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	var err error
	if required.End > s.fr.Length() {
		err = &memmap.BusError{linuxerr.EFAULT}
	}
	if source := optional.Intersect(memmap.MappableRange{0, s.fr.Length()}); source.Length() != 0 {
		return []memmap.Translation{
			{
				Source: source,
				File:   s.mfp.MemoryFile(),
				Offset: s.fr.Start + source.Start,
				Perms:  hostarch.AnyAccess,
			},
		}, err
	}
	return nil, err
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (s *Shm) InvalidateUnsavable(ctx context.Context) error {
	return nil
}

// AttachOpts describes various flags passed to shmat(2).
type AttachOpts struct {
	Execute  bool
	Readonly bool
	Remap    bool
}

// ConfigureAttach creates an mmap configuration for the segment with the
// requested attach options.
//
// Postconditions: The returned MMapOpts are valid only as long as a reference
// continues to be held on s.
func (s *Shm) ConfigureAttach(ctx context.Context, addr hostarch.Addr, opts AttachOpts) (memmap.MMapOpts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingDestruction && s.ReadRefs() == 0 {
		return memmap.MMapOpts{}, linuxerr.EIDRM
	}

	creds := auth.CredentialsFromContext(ctx)
	ats := vfs.MayRead
	if !opts.Readonly {
		ats |= vfs.MayWrite
	}
	if opts.Execute {
		ats |= vfs.MayExec
	}
	if !s.obj.CheckPermissions(creds, ats) {
		// "The calling process does not have the required permissions for the
		// requested attach type, and does not have the CAP_IPC_OWNER capability
		// in the user namespace that governs its IPC namespace." - man shmat(2)
		return memmap.MMapOpts{}, linuxerr.EACCES
	}
	return memmap.MMapOpts{
		Length: s.size,
		Offset: 0,
		Addr:   addr,
		Fixed:  opts.Remap,
		Perms: hostarch.AccessType{
			Read:    true,
			Write:   !opts.Readonly,
			Execute: opts.Execute,
		},
		MaxPerms:        hostarch.AnyAccess,
		Mappable:        s,
		MappingIdentity: s,
	}, nil
}

// EffectiveSize returns the size of the underlying shared memory segment. This
// may be larger than the requested size at creation, due to rounding to page
// boundaries.
func (s *Shm) EffectiveSize() uint64 {
	return s.effectiveSize
}

// IPCStat returns information about a shm. See shmctl(IPC_STAT).
func (s *Shm) IPCStat(ctx context.Context) (*linux.ShmidDS, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// "The caller must have read permission on the shared memory segment."
	//   - man shmctl(2)
	creds := auth.CredentialsFromContext(ctx)
	if !s.obj.CheckPermissions(creds, vfs.MayRead) {
		// "IPC_STAT or SHM_STAT is requested and shm_perm.mode does not allow
		// read access for shmid, and the calling process does not have the
		// CAP_IPC_OWNER capability in the user namespace that governs its IPC
		// namespace." - man shmctl(2)
		return nil, linuxerr.EACCES
	}

	var mode uint16
	if s.pendingDestruction {
		mode |= linux.SHM_DEST
	}

	// Use the reference count as a rudimentary count of the number of
	// attaches. We exclude:
	//
	// 1. The reference the caller holds.
	// 2. The self-reference held by s prior to destruction.
	//
	// Note that this may still overcount by including transient references
	// used in concurrent calls.
	nattach := uint64(s.ReadRefs()) - 1
	if !s.pendingDestruction {
		nattach--
	}

	ds := &linux.ShmidDS{
		ShmPerm: linux.IPCPerm{
			Key:  uint32(s.obj.Key),
			UID:  uint32(creds.UserNamespace.MapFromKUID(s.obj.OwnerUID)),
			GID:  uint32(creds.UserNamespace.MapFromKGID(s.obj.OwnerGID)),
			CUID: uint32(creds.UserNamespace.MapFromKUID(s.obj.CreatorUID)),
			CGID: uint32(creds.UserNamespace.MapFromKGID(s.obj.CreatorGID)),
			Mode: mode | uint16(s.obj.Mode),
			Seq:  0, // IPC sequences not supported.
		},
		ShmSegsz:   s.size,
		ShmAtime:   s.attachTime.TimeT(),
		ShmDtime:   s.detachTime.TimeT(),
		ShmCtime:   s.changeTime.TimeT(),
		ShmCpid:    s.creatorPID,
		ShmLpid:    s.lastAttachDetachPID,
		ShmNattach: nattach,
	}

	return ds, nil
}

// Set modifies attributes for a segment. See shmctl(IPC_SET).
func (s *Shm) Set(ctx context.Context, ds *linux.ShmidDS) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.obj.Set(ctx, &ds.ShmPerm); err != nil {
		return err
	}

	s.changeTime = ktime.NowFromContext(ctx)
	return nil
}

// MarkDestroyed marks a segment for destruction. The segment is actually
// destroyed once it has no references. MarkDestroyed may be called multiple
// times, and is safe to call after a segment has already been destroyed. See
// shmctl(IPC_RMID).
func (s *Shm) MarkDestroyed(ctx context.Context) {
	s.registry.dissociateKey(s)

	s.mu.Lock()
	if s.pendingDestruction {
		s.mu.Unlock()
		return
	}
	s.pendingDestruction = true
	s.mu.Unlock()

	// Drop the self-reference so destruction occurs when all
	// external references are gone.
	//
	// N.B. This cannot be the final DecRef, as the caller also
	// holds a reference.
	s.DecRef(ctx)
	return
}
