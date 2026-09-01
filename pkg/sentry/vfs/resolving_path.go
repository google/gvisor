// Copyright 2019 The gVisor Authors.
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

package vfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
)

// ResolvingPath represents the state of an in-progress path resolution, shared
// between VFS and FilesystemImpl methods that take a path.
//
// From the perspective of FilesystemImpl methods, a ResolvingPath represents a
// starting Dentry on the associated Filesystem (on which a reference is
// already held), a stream of path components relative to that Dentry, and
// elements of the invoking Context that are commonly required by
// FilesystemImpl methods.
//
// ResolvingPath is loosely analogous to Linux's struct nameidata.
//
// +stateify savable
type ResolvingPath struct {
	vfs   *VirtualFilesystem
	root  VirtualDentry // refs borrowed from PathOperation
	mount *Mount
	start *Dentry
	pit   fspath.Iterator

	flags     uint16
	mustBeDir bool  // final file must be a directory?
	symlinks  uint8 // number of symlinks traversed
	curPart   uint8 // index into parts

	creds *auth.Credentials

	// Data associated with resolve*Errors, stored in ResolvingPath so that
	// those errors don't need to allocate.
	nextMount        *Mount  // ref held if not nil
	nextStart        *Dentry // ref held if not nil
	absSymlinkTarget fspath.Path

	// ResolvingPath tracks relative paths, which is updated whenever a relative
	// symlink is encountered.
	parts [1 + linux.MaxSymlinkTraversals]fspath.Iterator

	// mountSeq stores the vfs.mounts.seq sequence number at the beginning of
	// the walk if flags contains rpflagsBeneath or rpflagsInRoot.
	//
	// It is used to fail scoped traversals that race against a mount tree change.
	mountSeq sync.SeqCountEpoch

	// renameState stores the vfs.renameState at the beginning of
	// the walk if flags contains rpflagsBeneath or rpflagsInRoot.
	//
	// It is used to fail scoped traversals that race against a rename.
	// renameState contains both a sequence counter and a currently-in-progress
	// renames counter. The sequence count is used to detect renames that have
	// started and ended since the walk began; the in-progress counter is used to
	// detect renames that are in-progress during a particular walk step.
	//
	// The checks are performed on every `..` by checkDotDotRace, at the end of
	// CheckRoot and CheckMount. Since these methods' callers will have fetched
	// the next dentry to traverse prior to calling, checking at the end ensures
	// that the previously-fetched dentry is up-to-date and did not race with a
	// mount or rename.
	renameState uint64
}

const (
	rpflagsHaveMountRef       = 1 << iota // do we hold a reference on mount?
	rpflagsHaveStartRef                   // do we hold a reference on start?
	rpflagsFollowFinalSymlink             // same as PathOperation.FollowFinalSymlink
	rpflagsBeneath                        // same as RESOLVE_BENEATH
	rpflagsInRoot                         // same as RESOLVE_IN_ROOT
	rpflagsNoMagicLinks                   // same as RESOLVE_NO_MAGICLINKS
	rpflagsNoSymlinks                     // same as RESOLVE_NO_SYMLINKS
	rpflagsNoXDev                         // same as RESOLVE_NO_XDEV
)

func init() {
	if maxParts := len(ResolvingPath{}.parts); maxParts > 255 {
		panic(fmt.Sprintf("uint8 is insufficient to accommodate len(ResolvingPath.parts) (%d)", maxParts))
	}
}

// Error types that communicate state from the FilesystemImpl-caller,
// VFS-callee side of path resolution (i.e. errors returned by
// ResolvingPath.Resolve*()) to the VFS-caller, FilesystemImpl-callee side
// (i.e. VFS methods => ResolvingPath.handleError()). These are empty structs
// rather than error values because Go doesn't support non-primitive constants,
// so error "constants" are really mutable vars, necessitating somewhat
// expensive interface object comparisons.

// +stateify savable
type resolveMountRootOrJumpError struct{}

// Error implements error.Error.
func (resolveMountRootOrJumpError) Error() string {
	return "resolving mount root or jump"
}

// +stateify savable
type resolveMountPointError struct{}

// Error implements error.Error.
func (resolveMountPointError) Error() string {
	return "resolving mount point"
}

// +stateify savable
type resolveAbsSymlinkError struct{}

// Error implements error.Error.
func (resolveAbsSymlinkError) Error() string {
	return "resolving absolute symlink"
}

var resolvingPathPool = sync.Pool{
	New: func() any {
		return &ResolvingPath{}
	},
}

// scoped indicates whether rp represents a scoped traversal.
func (rp *ResolvingPath) scoped() bool {
	return rp.flags&(rpflagsBeneath|rpflagsInRoot) != 0
}

// getResolvingPath gets a new ResolvingPath from the pool. Caller must call
// ResolvingPath.Release() when done.
func (vfs *VirtualFilesystem) getResolvingPath(creds *auth.Credentials, pop *PathOperation) *ResolvingPath {
	resolveBeneath := pop.ResolveFlags&linux.RESOLVE_BENEATH != 0
	resolveInRoot := pop.ResolveFlags&linux.RESOLVE_IN_ROOT != 0
	scoped := resolveBeneath || resolveInRoot

	if checkInvariants && resolveBeneath {
		// Check invariants for RESOLVE_BENEATH
		if pop.Path.Absolute {
			panic("VirtualFilesystem.getResolvingPath() called with RESOLVE_BENEATH and absolute pop.Path")
		}
	}

	rp := resolvingPathPool.Get().(*ResolvingPath)
	rp.vfs = vfs
	rp.root = pop.Root
	rp.mount = pop.Start.mount
	rp.start = pop.Start.dentry
	rp.pit = pop.Path.Begin
	rp.flags = 0
	if pop.FollowFinalSymlink {
		rp.flags |= rpflagsFollowFinalSymlink
	}
	if resolveBeneath {
		rp.flags |= rpflagsBeneath
	}
	if resolveInRoot {
		rp.flags |= rpflagsInRoot
	}
	if scoped {
		rp.root = pop.Start
		rp.mountSeq = vfs.mounts.seq.BeginRead()
		rp.renameState = vfs.renameState.Load()
	}
	if pop.ResolveFlags&linux.RESOLVE_NO_MAGICLINKS != 0 {
		rp.flags |= rpflagsNoMagicLinks
	}
	if pop.ResolveFlags&linux.RESOLVE_NO_SYMLINKS != 0 {
		rp.flags |= rpflagsNoSymlinks
	}
	if pop.ResolveFlags&linux.RESOLVE_NO_XDEV != 0 {
		rp.flags |= rpflagsNoXDev
	}
	rp.mustBeDir = pop.Path.Dir
	rp.symlinks = 0
	rp.curPart = 0
	rp.creds = creds
	rp.parts[0] = pop.Path.Begin
	return rp
}

// Copy creates another ResolvingPath with the same state as the original.
// Copies are independent, using the copy does not change the original and
// vice-versa.
//
// Caller must call Resease() when done.
func (rp *ResolvingPath) Copy() *ResolvingPath {
	copy := resolvingPathPool.Get().(*ResolvingPath)
	*copy = *rp // All fields all shallow copiable.

	// Take extra reference for the copy if the original had them.
	if copy.flags&rpflagsHaveStartRef != 0 {
		copy.start.IncRef()
	}
	if copy.flags&rpflagsHaveMountRef != 0 {
		copy.mount.IncRef()
	}
	// Reset error state.
	copy.nextStart = nil
	copy.nextMount = nil
	return copy
}

// Release decrements references if needed and returns the object to the pool.
func (rp *ResolvingPath) Release(ctx context.Context) {
	rp.root = VirtualDentry{}
	rp.decRefStartAndMount(ctx)
	rp.mount = nil
	rp.start = nil
	rp.releaseErrorState(ctx)
	resolvingPathPool.Put(rp)
}

func (rp *ResolvingPath) decRefStartAndMount(ctx context.Context) {
	if rp.flags&rpflagsHaveStartRef != 0 {
		rp.start.DecRef(ctx)
	}
	if rp.flags&rpflagsHaveMountRef != 0 {
		rp.mount.DecRef(ctx)
	}
}

func (rp *ResolvingPath) releaseErrorState(ctx context.Context) {
	if rp.nextStart != nil {
		rp.nextStart.DecRef(ctx)
		rp.nextStart = nil
	}
	if rp.nextMount != nil {
		rp.nextMount.DecRef(ctx)
		rp.nextMount = nil
	}
}

func (rp *ResolvingPath) checkDotDotRace() bool {
	// Did we race with a mount?
	if !rp.vfs.mounts.seq.ReadOk(rp.mountSeq) {
		return false
	}
	// Was a rename operation in progress at the start of the walk?
	if rp.renameState&renameInProgressMask != 0 {
		return false
	}
	// Is there a new in-flight rename operation since the start of the walk,
	// or has one completed since then?
	if rp.vfs.renameState.Load() != rp.renameState {
		return false
	}
	return true
}

// VirtualFilesystem returns the containing VirtualFilesystem.
func (rp *ResolvingPath) VirtualFilesystem() *VirtualFilesystem {
	return rp.vfs
}

// Credentials returns the credentials of rp's provider.
func (rp *ResolvingPath) Credentials() *auth.Credentials {
	return rp.creds
}

// Mount returns the Mount on which path resolution is currently occurring. It
// does not take a reference on the returned Mount.
func (rp *ResolvingPath) Mount() *Mount {
	return rp.mount
}

// Start returns the starting Dentry represented by rp. It does not take a
// reference on the returned Dentry.
func (rp *ResolvingPath) Start() *Dentry {
	return rp.start
}

// Done returns true if there are no remaining path components in the stream
// represented by rp.
func (rp *ResolvingPath) Done() bool {
	// We don't need to check for rp.curPart == 0 because rp.Advance() won't
	// set rp.pit to a terminal iterator otherwise.
	return !rp.pit.Ok()
}

// Final returns true if there is exactly one remaining path component in the
// stream represented by rp.
//
// Preconditions: !rp.Done().
func (rp *ResolvingPath) Final() bool {
	return rp.curPart == 0 && !rp.pit.NextOk()
}

// Component returns the current path component in the stream represented by
// rp.
//
// Preconditions: !rp.Done().
func (rp *ResolvingPath) Component() string {
	if checkInvariants {
		if !rp.pit.Ok() {
			panic("ResolvingPath.Component() called at end of relative path")
		}
	}
	return rp.pit.String()
}

// Advance advances the stream of path components represented by rp.
//
// Preconditions: !rp.Done().
func (rp *ResolvingPath) Advance() {
	if checkInvariants {
		if !rp.pit.Ok() {
			panic("ResolvingPath.Advance() called at end of relative path")
		}
	}
	next := rp.pit.Next()
	if next.Ok() || rp.curPart == 0 { // have next component, or at end of path
		rp.pit = next
	} else { // at end of path segment, continue with next one
		rp.curPart--
		rp.pit = rp.parts[rp.curPart]
	}
}

// GetComponents emits all the remaining path components in rp. It does *not*
// update rp state. It halts if emit() returns false. If excludeLast is true,
// then the last path component is not emitted.
func (rp *ResolvingPath) GetComponents(excludeLast bool, emit func(string) bool) {
	// Copy rp state.
	cur := rp.pit
	curPart := rp.curPart
	for cur.Ok() {
		if excludeLast && curPart == 0 && !cur.NextOk() {
			break
		}
		if !emit(cur.String()) {
			break
		}
		cur = cur.Next()
		if !cur.Ok() && curPart > 0 {
			curPart--
			cur = rp.parts[curPart]
		}
	}
}

func (rp *ResolvingPath) checkRoot(ctx context.Context, d *Dentry) (bool, error) {
	beneath := rp.flags&rpflagsBeneath != 0
	if d == rp.root.dentry && rp.mount == rp.root.mount {
		// At contextual VFS root (due to e.g. chroot(2)).
		if beneath {
			// For RESOLVE_BENEATH, trying to traverse above the root
			// (which in this case is set from dirfd) should fail.
			return false, linuxerr.EXDEV
		}
		return true, nil
	} else if d == rp.mount.root {
		// At mount root ...
		vd := rp.vfs.getMountpointAt(ctx, rp.mount, rp.root)
		if vd.Ok() {
			// ... of non-root mount.
			if rp.flags&rpflagsNoXDev != 0 {
				// Disallow climbing up into a new mount for RESOLVE_NO_XDEV traversals
				vd.DecRef(ctx)
				return false, linuxerr.EXDEV
			}
			rp.nextMount = vd.mount
			rp.nextStart = vd.dentry
			return false, resolveMountRootOrJumpError{}
		}
		// ... of root mount.
		if beneath {
			return false, linuxerr.EXDEV
		}
		return true, nil
	}
	return false, nil
}

// CheckRoot is called after loading but before resolving the parent of the
// Dentry d. If the Dentry is contextually a VFS root, such that path resolution
// should treat d's parent as itself, CheckRoot returns (true, nil). If the Dentry
// is the root of a non-root mount, such that path resolution should switch to another
// Mount, CheckRoot returns (unspecified, resolve error). If another error is
// encountered, CheckRoot returns (unspecified, linuxerr error). Otherwise, path
// resolution should resolve d's parent normally, and CheckRoot returns (false,
// nil).
func (rp *ResolvingPath) CheckRoot(ctx context.Context, d *Dentry) (bool, error) {
	isRoot, err := rp.checkRoot(ctx, d)
	// For scoped mounts, if the caller would continue the walk after CheckRoot,
	// we must check if we raced with a mount or rename operation.
	if rp.scoped() && (err == nil || rp.canHandleError(err)) && !rp.checkDotDotRace() {
		err = linuxerr.EAGAIN
	}
	return isRoot, err
}

func (rp *ResolvingPath) checkMount(ctx context.Context, d *Dentry) error {
	if !d.isMounted() {
		return nil
	}
	if mnt := rp.vfs.getMountAt(ctx, rp.mount, d); mnt != nil {
		if rp.flags&rpflagsNoXDev != 0 {
			// Don't cross a mount point for RESOLVE_NO_XDEV traversals
			mnt.DecRef(ctx)
			return linuxerr.EXDEV
		}

		rp.nextMount = mnt
		return resolveMountPointError{}
	}
	return nil
}

// CheckMount is called after resolving the parent or child of another Dentry
// to d. If d is a mount point, such that path resolution should switch to
// another Mount, CheckMount returns a non-nil error. Otherwise, CheckMount
// returns nil.
func (rp *ResolvingPath) CheckMount(ctx context.Context, d *Dentry) error {
	err := rp.checkMount(ctx, d)
	// For `..` on scoped mounts, if the caller would continue the walk after
	// CheckMount, we must check if we raced with a mount or rename operation.
	if rp.scoped() && rp.Component() == ".." && (err == nil || rp.canHandleError(err)) && !rp.checkDotDotRace() {
		return linuxerr.EAGAIN
	}
	return err
}

// ShouldFollowSymlink returns true if, supposing that the current path
// component in pcs represents a symbolic link, the symbolic link should be
// followed.
//
// If path is terminated with '/', the '/' is considered the last element and
// any symlink before that is followed:
//
//   - For most non-creating walks, the last path component is handled by
//     fs/namei.c:lookup_last(), which sets LOOKUP_FOLLOW if the first byte
//     after the path component is non-NULL (which is only possible if it's '/')
//     and the path component is of type LAST_NORM.
//
//   - For open/openat/openat2 without O_CREAT, the last path component is
//     handled by fs/namei.c:do_last(), which does the same, though without the
//     LAST_NORM check.
//
// Preconditions: !rp.Done().
func (rp *ResolvingPath) ShouldFollowSymlink() bool {
	// Non-final symlinks are always followed. Paths terminated with '/' are also
	// always followed.
	return rp.flags&rpflagsFollowFinalSymlink != 0 || !rp.Final() || rp.MustBeDir()
}

// HandleSymlink is called when the current path component is a symbolic link
// to the given target. If the calling Filesystem method should continue path
// traversal, HandleSymlink updates the path component stream to reflect the
// symlink target and returns nil. Otherwise it returns a non-nil error. It
// also returns whether the symlink was successfully followed, which can be
// true even when a non-nil error like resolveAbsSymlinkError is returned.
//
// Preconditions: !rp.Done().
//
// Postconditions: If HandleSymlink returns a nil error, then !rp.Done().
func (rp *ResolvingPath) HandleSymlink(target string) (bool, error) {
	if rp.symlinks >= linux.MaxSymlinkTraversals || rp.flags&rpflagsNoSymlinks != 0 {
		return false, linuxerr.ELOOP
	}
	if len(target) == 0 {
		return false, linuxerr.ENOENT
	}
	rp.symlinks++
	targetPath := fspath.Parse(target)
	if targetPath.Absolute {
		if rp.flags&rpflagsBeneath != 0 {
			// RESOLVE_BENEATH traversals reject absolute symlinks
			return true, linuxerr.EXDEV
		}
		if rp.flags&rpflagsNoXDev != 0 && rp.mount != rp.root.mount {
			// Absolute symlinks restart traversal at rp.root, so RESOLVE_NO_XDEV
			// traversals should only allow them if the root mount is the same one
			// we're currently on.
			//
			// Technically, Linux has an extra requirement: nd->root (equivalent to
			// rp.root) must have *been set*. It's initialized lazily, only in three
			// cases: .., absolute paths, and absolute symlinks. However, in the latter
			// case, the initialization occurs *after* the NO_XDEV check, so the NO_XDEV
			// check can occur with a null traversal root.
			//
			// This leads to strange situations. For example, on a system with a
			// *single* mount, on which one would expect NO_XDEV to have no effect,
			// the following call fails:
			//   openat2(dirfd /, "absolute-link", RESOLVE_NO_XDEV) -> EXDEV
			// whereas the following call succeeds, since .. causes nd->root to be set:
			//   openat2(dirfd /, "subdir/../absolute-link", RESOLVE_NO_XDEV) -> success
			//
			// This is apparently a Linux bug. In gVisor, rp.root is always set, so both
			// of the above calls would succeed. There's no harm in being a little more
			// permissive than Linux here (the traversal will still never cross a mount
			// boundary).
			return true, linuxerr.EXDEV
		}
		// For RESOLVE_IN_ROOT traversals, traversal will be restarted at rp.root
		// which in this case is bounded by the dirfd
		rp.absSymlinkTarget = targetPath
		return true, resolveAbsSymlinkError{}
	}
	// Consume the path component that represented the symlink.
	rp.Advance()
	// Prepend the symlink target to the relative path.
	if checkInvariants {
		if !targetPath.HasComponents() {
			panic(fmt.Sprintf("non-empty pathname %q parsed to relative path with no components", target))
		}
	}
	rp.relpathPrepend(targetPath)
	return true, nil
}

// Preconditions: path.HasComponents().
func (rp *ResolvingPath) relpathPrepend(path fspath.Path) {
	if rp.pit.Ok() {
		rp.parts[rp.curPart] = rp.pit
		rp.pit = path.Begin
		rp.curPart++
	} else {
		// The symlink was the final path component, so now the symlink target
		// is the whole path.
		rp.pit = path.Begin
		// Symlink targets can set rp.mustBeDir (if they end in a trailing /),
		// but can't unset it.
		if path.Dir {
			rp.mustBeDir = true
		}
	}
}

// HandleJump is called when the current path component is a "magic" link to
// the given VirtualDentry, like /proc/[pid]/fd/[fd]. If the calling Filesystem
// method should continue path traversal, HandleJump updates the path
// component stream to reflect the magic link target and returns nil. Otherwise
// it returns a non-nil error. It also returns whether the magic link was
// followed, which can be true even when a non-nil error like
// resolveMountRootOrJumpError is returned.
//
// Preconditions: !rp.Done().
func (rp *ResolvingPath) HandleJump(target VirtualDentry) (bool, error) {
	if rp.symlinks >= linux.MaxSymlinkTraversals {
		return false, linuxerr.ELOOP
	}
	if rp.flags&rpflagsNoMagicLinks != 0 || rp.flags&rpflagsNoSymlinks != 0 {
		// Reject magic links for RESOLVE_NO_SYMLINKS or RESOLVE_NO_MAGICLINKS traversals.
		return false, linuxerr.ELOOP
	}
	if rp.flags&rpflagsNoXDev != 0 && target.mount != rp.mount {
		// Reject magic links across mounts when RESOLVE_NOXDEV is set.
		return false, linuxerr.EXDEV
	}
	if rp.scoped() {
		// Linux currently rejects magic links for all scoped traversals.
		return false, linuxerr.EXDEV
	}
	rp.symlinks++
	// Consume the path component that represented the magic link.
	rp.Advance()
	// Unconditionally return a resolveMountRootOrJumpError, even if the Mount
	// isn't changing, to force restarting at the new Dentry.
	target.IncRef()
	rp.nextMount = target.mount
	rp.nextStart = target.dentry
	return true, resolveMountRootOrJumpError{}
}

func (rp *ResolvingPath) handleError(ctx context.Context, err error) bool {
	switch err.(type) {
	case resolveMountRootOrJumpError:
		// Switch to the new Mount. We hold references on the Mount and Dentry.
		rp.decRefStartAndMount(ctx)
		rp.mount = rp.nextMount
		rp.start = rp.nextStart
		rp.flags |= rpflagsHaveMountRef | rpflagsHaveStartRef
		rp.nextMount = nil
		rp.nextStart = nil
		// Don't consume the path component that caused us to traverse
		// through the mount root - i.e. the ".." - because we still need to
		// resolve the mount point's parent in the new FilesystemImpl.
		//
		// Restart path resolution on the new Mount. Don't bother calling
		// rp.releaseErrorState() since we already set nextMount and nextStart
		// to nil above.
		return true

	case resolveMountPointError:
		// Switch to the new Mount. We hold a reference on the Mount, but
		// borrow the reference on the mount root from the Mount.
		rp.decRefStartAndMount(ctx)
		rp.mount = rp.nextMount
		rp.start = rp.nextMount.root
		rp.flags = rp.flags&^rpflagsHaveStartRef | rpflagsHaveMountRef
		rp.nextMount = nil
		// Consume the path component that represented the mount point.
		rp.Advance()
		// Restart path resolution on the new Mount.
		rp.releaseErrorState(ctx)
		return true

	case resolveAbsSymlinkError:
		// Switch to the new Mount. References are borrowed from rp.root.
		rp.decRefStartAndMount(ctx)
		rp.mount = rp.root.mount
		rp.start = rp.root.dentry
		rp.flags &^= rpflagsHaveMountRef | rpflagsHaveStartRef
		// Consume the path component that represented the symlink.
		rp.Advance()
		if rp.absSymlinkTarget.HasComponents() {
			// Prepend the symlink target to the relative path.
			rp.relpathPrepend(rp.absSymlinkTarget)
		}
		// Restart path resolution on the new Mount.
		rp.releaseErrorState(ctx)
		return true

	default:
		// Not an error we can handle.
		return false
	}
}

// canHandleError returns true if err is an error returned by rp.Resolve*()
// that rp.handleError() may attempt to handle.
func (rp *ResolvingPath) canHandleError(err error) bool {
	switch err.(type) {
	case resolveMountRootOrJumpError, resolveMountPointError, resolveAbsSymlinkError:
		return true
	default:
		return false
	}
}

// MustBeDir returns true if the file traversed by rp must be a directory.
func (rp *ResolvingPath) MustBeDir() bool {
	return rp.mustBeDir
}

// finalizeScoped must be called by a VFS method that supports scoped traversals
// (RESOLVE_BENEATH and/or RESOLVE_IN_ROOT) once a resolving path has been fully
// resolved into a dentry.
//
// It performs a final check that the resolved path is underneath the scope specified
// by dirfd. It is analogous to the LOOKUP_IS_SCOPED branch in Linux's fs/namei.c.
//
// The extra check is necessary at the end for two reasons:
//   - as an extra check in case a bug in the path traversal allows a scoped
//     traversal to escape, and
//   - because the mountSeq sequence number used to detect races with mount operations is
//     only 32 bits, if some crazy person manages to pull off an exactly 2^32-mount overflow
//     during the path traversal window, this check would catch that.
//
// It is not *sufficient* because scoped lookups guarantee that escape occurs at no point
// during the traversal, not just that the final resolved path is appropriately scoped.
func (rp *ResolvingPath) finalizeScoped(ctx context.Context, resolvedVD VirtualDentry) error {
	if rp.scoped() {
		rp.vfs.lockMounts()
		ok := rp.vfs.isPathReachable(ctx, rp.root, resolvedVD)
		rp.vfs.unlockMounts(ctx)
		if !ok {
			return linuxerr.EXDEV
		}
	}

	return nil
}
