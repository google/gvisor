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
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
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
type ResolvingPath struct {
	vfs   *VirtualFilesystem
	root  VirtualDentry // refs borrowed from PathOperation
	mount *Mount
	start *Dentry
	pit   fspath.Iterator

	flags         uint16
	mustBeDir     bool // final file must be a directory?
	mustBeDirOrig bool
	symlinks      uint8 // number of symlinks traversed
	symlinksOrig  uint8
	curPart       uint8 // index into parts
	numOrigParts  uint8

	creds *auth.Credentials

	// Data associated with resolve*Errors, stored in ResolvingPath so that
	// those errors don't need to allocate.
	nextMount        *Mount  // ref held if not nil
	nextStart        *Dentry // ref held if not nil
	absSymlinkTarget fspath.Path

	// ResolvingPath must track up to two relative paths: the "current"
	// relative path, which is updated whenever a relative symlink is
	// encountered, and the "original" relative path, which is updated from the
	// current relative path by handleError() when resolution must change
	// filesystems (due to reaching a mount boundary or absolute symlink) and
	// overwrites the current relative path when Restart() is called.
	parts     [1 + linux.MaxSymlinkTraversals]fspath.Iterator
	origParts [1 + linux.MaxSymlinkTraversals]fspath.Iterator
}

const (
	rpflagsHaveMountRef       = 1 << iota // do we hold a reference on mount?
	rpflagsHaveStartRef                   // do we hold a reference on start?
	rpflagsFollowFinalSymlink             // same as PathOperation.FollowFinalSymlink
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

type resolveMountRootOrJumpError struct{}

// Error implements error.Error.
func (resolveMountRootOrJumpError) Error() string {
	return "resolving mount root or jump"
}

type resolveMountPointError struct{}

// Error implements error.Error.
func (resolveMountPointError) Error() string {
	return "resolving mount point"
}

type resolveAbsSymlinkError struct{}

// Error implements error.Error.
func (resolveAbsSymlinkError) Error() string {
	return "resolving absolute symlink"
}

var resolvingPathPool = sync.Pool{
	New: func() interface{} {
		return &ResolvingPath{}
	},
}

func (vfs *VirtualFilesystem) getResolvingPath(creds *auth.Credentials, pop *PathOperation) *ResolvingPath {
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
	rp.mustBeDir = pop.Path.Dir
	rp.mustBeDirOrig = pop.Path.Dir
	rp.symlinks = 0
	rp.curPart = 0
	rp.numOrigParts = 1
	rp.creds = creds
	rp.parts[0] = pop.Path.Begin
	rp.origParts[0] = pop.Path.Begin
	return rp
}

func (vfs *VirtualFilesystem) putResolvingPath(ctx context.Context, rp *ResolvingPath) {
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

// Restart resets the stream of path components represented by rp to its state
// on entry to the current FilesystemImpl method.
func (rp *ResolvingPath) Restart(ctx context.Context) {
	rp.pit = rp.origParts[rp.numOrigParts-1]
	rp.mustBeDir = rp.mustBeDirOrig
	rp.symlinks = rp.symlinksOrig
	rp.curPart = rp.numOrigParts - 1
	copy(rp.parts[:], rp.origParts[:rp.numOrigParts])
	rp.releaseErrorState(ctx)
}

func (rp *ResolvingPath) relpathCommit() {
	rp.mustBeDirOrig = rp.mustBeDir
	rp.symlinksOrig = rp.symlinks
	rp.numOrigParts = rp.curPart + 1
	copy(rp.origParts[:rp.curPart], rp.parts[:])
	rp.origParts[rp.curPart] = rp.pit
}

// CheckRoot is called before resolving the parent of the Dentry d. If the
// Dentry is contextually a VFS root, such that path resolution should treat
// d's parent as itself, CheckRoot returns (true, nil). If the Dentry is the
// root of a non-root mount, such that path resolution should switch to another
// Mount, CheckRoot returns (unspecified, non-nil error). Otherwise, path
// resolution should resolve d's parent normally, and CheckRoot returns (false,
// nil).
func (rp *ResolvingPath) CheckRoot(ctx context.Context, d *Dentry) (bool, error) {
	if d == rp.root.dentry && rp.mount == rp.root.mount {
		// At contextual VFS root (due to e.g. chroot(2)).
		return true, nil
	} else if d == rp.mount.root {
		// At mount root ...
		vd := rp.vfs.getMountpointAt(ctx, rp.mount, rp.root)
		if vd.Ok() {
			// ... of non-root mount.
			rp.nextMount = vd.mount
			rp.nextStart = vd.dentry
			return false, resolveMountRootOrJumpError{}
		}
		// ... of root mount.
		return true, nil
	}
	return false, nil
}

// CheckMount is called after resolving the parent or child of another Dentry
// to d. If d is a mount point, such that path resolution should switch to
// another Mount, CheckMount returns a non-nil error. Otherwise, CheckMount
// returns nil.
func (rp *ResolvingPath) CheckMount(ctx context.Context, d *Dentry) error {
	if !d.isMounted() {
		return nil
	}
	if mnt := rp.vfs.getMountAt(ctx, rp.mount, d); mnt != nil {
		rp.nextMount = mnt
		return resolveMountPointError{}
	}
	return nil
}

// ShouldFollowSymlink returns true if, supposing that the current path
// component in pcs represents a symbolic link, the symbolic link should be
// followed.
//
// If path is terminated with '/', the '/' is considered the last element and
// any symlink before that is followed:
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
// symlink target and returns nil. Otherwise it returns a non-nil error.
//
// Preconditions: !rp.Done().
//
// Postconditions: If HandleSymlink returns a nil error, then !rp.Done().
func (rp *ResolvingPath) HandleSymlink(target string) error {
	if rp.symlinks >= linux.MaxSymlinkTraversals {
		return syserror.ELOOP
	}
	if len(target) == 0 {
		return syserror.ENOENT
	}
	rp.symlinks++
	targetPath := fspath.Parse(target)
	if targetPath.Absolute {
		rp.absSymlinkTarget = targetPath
		return resolveAbsSymlinkError{}
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
	return nil
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
// method should continue path traversal, HandleMagicSymlink updates the path
// component stream to reflect the magic link target and returns nil. Otherwise
// it returns a non-nil error.
//
// Preconditions: !rp.Done().
func (rp *ResolvingPath) HandleJump(target VirtualDentry) error {
	if rp.symlinks >= linux.MaxSymlinkTraversals {
		return syserror.ELOOP
	}
	rp.symlinks++
	// Consume the path component that represented the magic link.
	rp.Advance()
	// Unconditionally return a resolveMountRootOrJumpError, even if the Mount
	// isn't changing, to force restarting at the new Dentry.
	target.IncRef()
	rp.nextMount = target.mount
	rp.nextStart = target.dentry
	return resolveMountRootOrJumpError{}
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
		// Commit the previous FileystemImpl's progress through the relative
		// path. (Don't consume the path component that caused us to traverse
		// through the mount root - i.e. the ".." - because we still need to
		// resolve the mount point's parent in the new FilesystemImpl.)
		rp.relpathCommit()
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
		// Commit the previous FilesystemImpl's progress through the relative
		// path.
		rp.relpathCommit()
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
		// Prepend the symlink target to the relative path.
		rp.relpathPrepend(rp.absSymlinkTarget)
		// Commit the previous FilesystemImpl's progress through the relative
		// path, including the symlink target we just prepended.
		rp.relpathCommit()
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
