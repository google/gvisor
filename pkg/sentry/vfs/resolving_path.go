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
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"
)

// ResolvingPath represents the state of an in-progress path resolution, shared
// between VFS and FilesystemImpl methods that take a path.
//
// From the perspective of FilesystemImpl methods, a ResolvingPath represents a
// starting Dentry on the associated Filesystem (on which a reference is
// already held) and a stream of path components relative to that Dentry.
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

type resolveMountRootError struct{}

// Error implements error.Error.
func (resolveMountRootError) Error() string {
	return "resolving mount root"
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

func (vfs *VirtualFilesystem) getResolvingPath(creds *auth.Credentials, pop *PathOperation) (*ResolvingPath, error) {
	path, err := fspath.Parse(pop.Pathname)
	if err != nil {
		return nil, err
	}
	rp := resolvingPathPool.Get().(*ResolvingPath)
	rp.vfs = vfs
	rp.root = pop.Root
	rp.mount = pop.Start.mount
	rp.start = pop.Start.dentry
	rp.pit = path.Begin
	rp.flags = 0
	if pop.FollowFinalSymlink {
		rp.flags |= rpflagsFollowFinalSymlink
	}
	rp.mustBeDir = path.Dir
	rp.mustBeDirOrig = path.Dir
	rp.symlinks = 0
	rp.curPart = 0
	rp.numOrigParts = 1
	rp.creds = creds
	rp.parts[0] = path.Begin
	rp.origParts[0] = path.Begin
	return rp, nil
}

func (vfs *VirtualFilesystem) putResolvingPath(rp *ResolvingPath) {
	rp.root = VirtualDentry{}
	rp.decRefStartAndMount()
	rp.mount = nil
	rp.start = nil
	rp.releaseErrorState()
	resolvingPathPool.Put(rp)
}

func (rp *ResolvingPath) decRefStartAndMount() {
	if rp.flags&rpflagsHaveStartRef != 0 {
		rp.start.decRef(rp.mount.fs)
	}
	if rp.flags&rpflagsHaveMountRef != 0 {
		rp.mount.decRef()
	}
}

func (rp *ResolvingPath) releaseErrorState() {
	if rp.nextStart != nil {
		rp.nextStart.decRef(rp.nextMount.fs)
		rp.nextStart = nil
	}
	if rp.nextMount != nil {
		rp.nextMount.decRef()
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
		rp.pit = rp.parts[rp.curPart-1]
	}
}

// Restart resets the stream of path components represented by rp to its state
// on entry to the current FilesystemImpl method.
func (rp *ResolvingPath) Restart() {
	rp.pit = rp.origParts[rp.numOrigParts-1]
	rp.mustBeDir = rp.mustBeDirOrig
	rp.symlinks = rp.symlinksOrig
	rp.curPart = rp.numOrigParts - 1
	copy(rp.parts[:], rp.origParts[:rp.numOrigParts])
	rp.releaseErrorState()
}

func (rp *ResolvingPath) relpathCommit() {
	rp.mustBeDirOrig = rp.mustBeDir
	rp.symlinksOrig = rp.symlinks
	rp.numOrigParts = rp.curPart + 1
	copy(rp.origParts[:rp.curPart], rp.parts[:])
	rp.origParts[rp.curPart] = rp.pit
}

// ResolveParent returns the VFS parent of d. It does not take a reference on
// the returned Dentry.
//
// Preconditions: There are no concurrent mutators of d.
//
// Postconditions: If the returned error is nil, then the returned Dentry is
// not nil.
func (rp *ResolvingPath) ResolveParent(d *Dentry) (*Dentry, error) {
	var parent *Dentry
	if d == rp.root.dentry && rp.mount == rp.root.mount {
		// At contextual VFS root.
		parent = d
	} else if d == rp.mount.root {
		// At mount root ...
		vd := rp.vfs.getMountpointAt(rp.mount, rp.root)
		if vd.Ok() {
			// ... of non-root mount.
			rp.nextMount = vd.mount
			rp.nextStart = vd.dentry
			return nil, resolveMountRootError{}
		}
		// ... of root mount.
		parent = d
	} else if d.parent == nil {
		// At filesystem root.
		parent = d
	} else {
		parent = d.parent
	}
	if parent.isMounted() {
		if mnt := rp.vfs.getMountAt(rp.mount, parent); mnt != nil {
			rp.nextMount = mnt
			return nil, resolveMountPointError{}
		}
	}
	return parent, nil
}

// ResolveChild returns the VFS child of d with the given name. It does not
// take a reference on the returned Dentry. If no such child exists,
// ResolveChild returns (nil, nil).
//
// Preconditions: There are no concurrent mutators of d.
func (rp *ResolvingPath) ResolveChild(d *Dentry, name string) (*Dentry, error) {
	child := d.children[name]
	if child == nil {
		return nil, nil
	}
	if child.isMounted() {
		if mnt := rp.vfs.getMountAt(rp.mount, child); mnt != nil {
			rp.nextMount = mnt
			return nil, resolveMountPointError{}
		}
	}
	return child, nil
}

// ResolveComponent returns the Dentry reached by starting at d and resolving
// the current path component in the stream represented by rp. It does not
// advance the stream. It does not take a reference on the returned Dentry. If
// no such Dentry exists, ResolveComponent returns (nil, nil).
//
// Preconditions: !rp.Done(). There are no concurrent mutators of d.
func (rp *ResolvingPath) ResolveComponent(d *Dentry) (*Dentry, error) {
	switch pc := rp.Component(); pc {
	case ".":
		return d, nil
	case "..":
		return rp.ResolveParent(d)
	default:
		return rp.ResolveChild(d, pc)
	}
}

// ShouldFollowSymlink returns true if, supposing that the current path
// component in pcs represents a symbolic link, the symbolic link should be
// followed.
//
// Preconditions: !rp.Done().
func (rp *ResolvingPath) ShouldFollowSymlink() bool {
	// Non-final symlinks are always followed.
	return rp.flags&rpflagsFollowFinalSymlink != 0 || !rp.Final()
}

// HandleSymlink is called when the current path component is a symbolic link
// to the given target. If the calling Filesystem method should continue path
// traversal, HandleSymlink updates the path component stream to reflect the
// symlink target and returns nil. Otherwise it returns a non-nil error.
//
// Preconditions: !rp.Done().
func (rp *ResolvingPath) HandleSymlink(target string) error {
	if rp.symlinks >= linux.MaxSymlinkTraversals {
		return syserror.ELOOP
	}
	targetPath, err := fspath.Parse(target)
	if err != nil {
		return err
	}
	rp.symlinks++
	if targetPath.Absolute {
		rp.absSymlinkTarget = targetPath
		return resolveAbsSymlinkError{}
	}
	if !targetPath.Begin.Ok() {
		panic(fmt.Sprintf("symbolic link has non-empty target %q that is both relative and has no path components?", target))
	}
	// Consume the path component that represented the symlink.
	rp.Advance()
	// Prepend the symlink target to the relative path.
	rp.relpathPrepend(targetPath)
	return nil
}

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

func (rp *ResolvingPath) handleError(err error) bool {
	switch err.(type) {
	case resolveMountRootError:
		// Switch to the new Mount. We hold references on the Mount and Dentry
		// (from VFS.getMountpointAt()).
		rp.decRefStartAndMount()
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
		// Switch to the new Mount. We hold a reference on the Mount (from
		// VFS.getMountAt()), but borrow the reference on the mount root from
		// the Mount.
		rp.decRefStartAndMount()
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
		rp.releaseErrorState()
		return true

	case resolveAbsSymlinkError:
		// Switch to the new Mount. References are borrowed from rp.root.
		rp.decRefStartAndMount()
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
		rp.releaseErrorState()
		return true

	default:
		// Not an error we can handle.
		return false
	}
}

// MustBeDir returns true if the file traversed by rp must be a directory.
func (rp *ResolvingPath) MustBeDir() bool {
	return rp.mustBeDir
}
