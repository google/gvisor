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

package p9

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
)

// ExtractErrno extracts a syscall.Errno from a error, best effort.
func ExtractErrno(err error) syscall.Errno {
	switch err {
	case os.ErrNotExist:
		return syscall.ENOENT
	case os.ErrExist:
		return syscall.EEXIST
	case os.ErrPermission:
		return syscall.EACCES
	case os.ErrInvalid:
		return syscall.EINVAL
	}

	// Attempt to unwrap.
	switch e := err.(type) {
	case syscall.Errno:
		return e
	case *os.PathError:
		return ExtractErrno(e.Err)
	case *os.SyscallError:
		return ExtractErrno(e.Err)
	}

	// Default case.
	log.Warningf("unknown error: %v", err)
	return syscall.EIO
}

// newErr returns a new error message from an error.
func newErr(err error) *Rlerror {
	return &Rlerror{Error: uint32(ExtractErrno(err))}
}

// handler is implemented for server-handled messages.
//
// See server.go for call information.
type handler interface {
	// Handle handles the given message.
	//
	// This may modify the server state. The handle function must return a
	// message which will be sent back to the client. It may be useful to
	// use newErr to automatically extract an error message.
	handle(cs *connState) message
}

// handle implements handler.handle.
func (t *Tversion) handle(cs *connState) message {
	if t.MSize == 0 {
		return newErr(syscall.EINVAL)
	}
	if t.MSize > maximumLength {
		return newErr(syscall.EINVAL)
	}
	atomic.StoreUint32(&cs.messageSize, t.MSize)
	requested, ok := parseVersion(t.Version)
	if !ok {
		return newErr(syscall.EINVAL)
	}
	// The server cannot support newer versions that it doesn't know about.  In this
	// case we return EAGAIN to tell the client to try again with a lower version.
	if requested > highestSupportedVersion {
		return newErr(syscall.EAGAIN)
	}
	// From Tversion(9P): "The server may respond with the client’s version
	// string, or a version string identifying an earlier defined protocol version".
	atomic.StoreUint32(&cs.version, requested)
	return &Rversion{
		MSize:   t.MSize,
		Version: t.Version,
	}
}

// handle implements handler.handle.
func (t *Tflush) handle(cs *connState) message {
	cs.WaitTag(t.OldTag)
	return &Rflush{}
}

// checkSafeName validates the name and returns nil or returns an error.
func checkSafeName(name string) error {
	if name != "" && !strings.Contains(name, "/") && name != "." && name != ".." {
		return nil
	}
	return syscall.EINVAL
}

// handle implements handler.handle.
func (t *Tclunk) handle(cs *connState) message {
	if !cs.DeleteFID(t.FID) {
		return newErr(syscall.EBADF)
	}
	return &Rclunk{}
}

// handle implements handler.handle.
func (t *Tremove) handle(cs *connState) message {
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	// Frustratingly, because we can't be guaranteed that a rename is not
	// occurring simultaneously with this removal, we need to acquire the
	// global rename lock for this kind of remove operation to ensure that
	// ref.parent does not change out from underneath us.
	//
	// This is why Tremove is a bad idea, and clients should generally use
	// Tunlinkat. All p9 clients will use Tunlinkat.
	err := ref.safelyGlobal(func() error {
		// Is this a root? Can't remove that.
		if ref.isRoot() {
			return syscall.EINVAL
		}

		// N.B. this remove operation is permitted, even if the file is open.
		// See also rename below for reasoning.

		// Is this file already deleted?
		if ref.isDeleted() {
			return syscall.EINVAL
		}

		// Retrieve the file's proper name.
		name := ref.parent.pathNode.nameFor(ref)

		// Attempt the removal.
		if err := ref.parent.file.UnlinkAt(name, 0); err != nil {
			return err
		}

		// Mark all relevant fids as deleted. We don't need to lock any
		// individual nodes because we already hold the global lock.
		ref.parent.markChildDeleted(name)
		return nil
	})

	// "The remove request asks the file server both to remove the file
	// represented by fid and to clunk the fid, even if the remove fails."
	//
	// "It is correct to consider remove to be a clunk with the side effect
	// of removing the file if permissions allow."
	// https://swtch.com/plan9port/man/man9/remove.html
	if !cs.DeleteFID(t.FID) {
		return newErr(syscall.EBADF)
	}
	if err != nil {
		return newErr(err)
	}

	return &Rremove{}
}

// handle implements handler.handle.
//
// We don't support authentication, so this just returns ENOSYS.
func (t *Tauth) handle(cs *connState) message {
	return newErr(syscall.ENOSYS)
}

// handle implements handler.handle.
func (t *Tattach) handle(cs *connState) message {
	// Ensure no authentication FID is provided.
	if t.Auth.AuthenticationFID != NoFID {
		return newErr(syscall.EINVAL)
	}

	// Must provide an absolute path.
	if path.IsAbs(t.Auth.AttachName) {
		// Trim off the leading / if the path is absolute. We always
		// treat attach paths as absolute and call attach with the root
		// argument on the server file for clarity.
		t.Auth.AttachName = t.Auth.AttachName[1:]
	}

	// Do the attach on the root.
	sf, err := cs.server.attacher.Attach()
	if err != nil {
		return newErr(err)
	}
	qid, valid, attr, err := sf.GetAttr(AttrMaskAll())
	if err != nil {
		sf.Close() // Drop file.
		return newErr(err)
	}
	if !valid.Mode {
		sf.Close() // Drop file.
		return newErr(syscall.EINVAL)
	}

	// Build a transient reference.
	root := &fidRef{
		server:   cs.server,
		parent:   nil,
		file:     sf,
		refs:     1,
		mode:     attr.Mode.FileType(),
		pathNode: cs.server.pathTree,
	}
	defer root.DecRef()

	// Attach the root?
	if len(t.Auth.AttachName) == 0 {
		cs.InsertFID(t.FID, root)
		return &Rattach{QID: qid}
	}

	// We want the same traversal checks to apply on attach, so always
	// attach at the root and use the regular walk paths.
	names := strings.Split(t.Auth.AttachName, "/")
	_, newRef, _, _, err := doWalk(cs, root, names, false)
	if err != nil {
		return newErr(err)
	}
	defer newRef.DecRef()

	// Insert the FID.
	cs.InsertFID(t.FID, newRef)
	return &Rattach{QID: qid}
}

// CanOpen returns whether this file open can be opened, read and written to.
//
// This includes everything except symlinks and sockets.
func CanOpen(mode FileMode) bool {
	return mode.IsRegular() || mode.IsDir() || mode.IsNamedPipe() || mode.IsBlockDevice() || mode.IsCharacterDevice()
}

// handle implements handler.handle.
func (t *Tlopen) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	ref.openedMu.Lock()
	defer ref.openedMu.Unlock()

	// Has it been opened already?
	if ref.opened || !CanOpen(ref.mode) {
		return newErr(syscall.EINVAL)
	}

	// Are flags valid?
	flags := t.Flags &^ OpenFlagsIgnoreMask
	if flags&^OpenFlagsModeMask != 0 {
		return newErr(syscall.EINVAL)
	}

	// Is this an attempt to open a directory as writable? Don't accept.
	if ref.mode.IsDir() && flags != ReadOnly {
		return newErr(syscall.EINVAL)
	}

	var (
		qid    QID
		ioUnit uint32
		osFile *fd.FD
	)
	if err := ref.safelyRead(func() (err error) {
		// Has it been deleted already?
		if ref.isDeleted() {
			return syscall.EINVAL
		}

		// Do the open.
		osFile, qid, ioUnit, err = ref.file.Open(t.Flags)
		return err
	}); err != nil {
		return newErr(err)
	}

	// Mark file as opened and set open mode.
	ref.opened = true
	ref.openFlags = t.Flags

	rlopen := &Rlopen{QID: qid, IoUnit: ioUnit}
	rlopen.SetFilePayload(osFile)
	return rlopen
}

func (t *Tlcreate) do(cs *connState, uid UID) (*Rlcreate, error) {
	// Don't allow complex names.
	if err := checkSafeName(t.Name); err != nil {
		return nil, err
	}

	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return nil, syscall.EBADF
	}
	defer ref.DecRef()

	var (
		osFile *fd.FD
		nsf    File
		qid    QID
		ioUnit uint32
		newRef *fidRef
	)
	if err := ref.safelyWrite(func() (err error) {
		// Don't allow creation from non-directories or deleted directories.
		if ref.isDeleted() || !ref.mode.IsDir() {
			return syscall.EINVAL
		}

		// Not allowed on open directories.
		if _, opened := ref.OpenFlags(); opened {
			return syscall.EINVAL
		}

		// Do the create.
		osFile, nsf, qid, ioUnit, err = ref.file.Create(t.Name, t.OpenFlags, t.Permissions, uid, t.GID)
		if err != nil {
			return err
		}

		newRef = &fidRef{
			server:    cs.server,
			parent:    ref,
			file:      nsf,
			opened:    true,
			openFlags: t.OpenFlags,
			mode:      ModeRegular,
			pathNode:  ref.pathNode.pathNodeFor(t.Name),
		}
		ref.pathNode.addChild(newRef, t.Name)
		ref.IncRef() // Acquire parent reference.
		return nil
	}); err != nil {
		return nil, err
	}

	// Replace the FID reference.
	cs.InsertFID(t.FID, newRef)

	rlcreate := &Rlcreate{Rlopen: Rlopen{QID: qid, IoUnit: ioUnit}}
	rlcreate.SetFilePayload(osFile)
	return rlcreate, nil
}

// handle implements handler.handle.
func (t *Tlcreate) handle(cs *connState) message {
	rlcreate, err := t.do(cs, NoUID)
	if err != nil {
		return newErr(err)
	}
	return rlcreate
}

// handle implements handler.handle.
func (t *Tsymlink) handle(cs *connState) message {
	rsymlink, err := t.do(cs, NoUID)
	if err != nil {
		return newErr(err)
	}
	return rsymlink
}

func (t *Tsymlink) do(cs *connState, uid UID) (*Rsymlink, error) {
	// Don't allow complex names.
	if err := checkSafeName(t.Name); err != nil {
		return nil, err
	}

	// Lookup the FID.
	ref, ok := cs.LookupFID(t.Directory)
	if !ok {
		return nil, syscall.EBADF
	}
	defer ref.DecRef()

	var qid QID
	if err := ref.safelyWrite(func() (err error) {
		// Don't allow symlinks from non-directories or deleted directories.
		if ref.isDeleted() || !ref.mode.IsDir() {
			return syscall.EINVAL
		}

		// Not allowed on open directories.
		if _, opened := ref.OpenFlags(); opened {
			return syscall.EINVAL
		}

		// Do the symlink.
		qid, err = ref.file.Symlink(t.Target, t.Name, uid, t.GID)
		return err
	}); err != nil {
		return nil, err
	}

	return &Rsymlink{QID: qid}, nil
}

// handle implements handler.handle.
func (t *Tlink) handle(cs *connState) message {
	// Don't allow complex names.
	if err := checkSafeName(t.Name); err != nil {
		return newErr(err)
	}

	// Lookup the FID.
	ref, ok := cs.LookupFID(t.Directory)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	// Lookup the other FID.
	refTarget, ok := cs.LookupFID(t.Target)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer refTarget.DecRef()

	if err := ref.safelyWrite(func() (err error) {
		// Don't allow create links from non-directories or deleted directories.
		if ref.isDeleted() || !ref.mode.IsDir() {
			return syscall.EINVAL
		}

		// Not allowed on open directories.
		if _, opened := ref.OpenFlags(); opened {
			return syscall.EINVAL
		}

		// Do the link.
		return ref.file.Link(refTarget.file, t.Name)
	}); err != nil {
		return newErr(err)
	}

	return &Rlink{}
}

// handle implements handler.handle.
func (t *Trenameat) handle(cs *connState) message {
	// Don't allow complex names.
	if err := checkSafeName(t.OldName); err != nil {
		return newErr(err)
	}
	if err := checkSafeName(t.NewName); err != nil {
		return newErr(err)
	}

	// Lookup the FID.
	ref, ok := cs.LookupFID(t.OldDirectory)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	// Lookup the other FID.
	refTarget, ok := cs.LookupFID(t.NewDirectory)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer refTarget.DecRef()

	// Perform the rename holding the global lock.
	if err := ref.safelyGlobal(func() (err error) {
		// Don't allow renaming across deleted directories.
		if ref.isDeleted() || !ref.mode.IsDir() || refTarget.isDeleted() || !refTarget.mode.IsDir() {
			return syscall.EINVAL
		}

		// Not allowed on open directories.
		if _, opened := ref.OpenFlags(); opened {
			return syscall.EINVAL
		}

		// Is this the same file? If yes, short-circuit and return success.
		if ref.pathNode == refTarget.pathNode && t.OldName == t.NewName {
			return nil
		}

		// Attempt the actual rename.
		if err := ref.file.RenameAt(t.OldName, refTarget.file, t.NewName); err != nil {
			return err
		}

		// Update the path tree.
		ref.renameChildTo(t.OldName, refTarget, t.NewName)
		return nil
	}); err != nil {
		return newErr(err)
	}

	return &Rrenameat{}
}

// handle implements handler.handle.
func (t *Tunlinkat) handle(cs *connState) message {
	// Don't allow complex names.
	if err := checkSafeName(t.Name); err != nil {
		return newErr(err)
	}

	// Lookup the FID.
	ref, ok := cs.LookupFID(t.Directory)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	if err := ref.safelyWrite(func() (err error) {
		// Don't allow deletion from non-directories or deleted directories.
		if ref.isDeleted() || !ref.mode.IsDir() {
			return syscall.EINVAL
		}

		// Not allowed on open directories.
		if _, opened := ref.OpenFlags(); opened {
			return syscall.EINVAL
		}

		// Before we do the unlink itself, we need to ensure that there
		// are no operations in flight on associated path node. The
		// child's path node lock must be held to ensure that the
		// unlinkat marking the child deleted below is atomic with
		// respect to any other read or write operations.
		//
		// This is one case where we have a lock ordering issue, but
		// since we always acquire deeper in the hierarchy, we know
		// that we are free of lock cycles.
		childPathNode := ref.pathNode.pathNodeFor(t.Name)
		childPathNode.opMu.Lock()
		defer childPathNode.opMu.Unlock()

		// Do the unlink.
		err = ref.file.UnlinkAt(t.Name, t.Flags)
		if err != nil {
			return err
		}

		// Mark the path as deleted.
		ref.markChildDeleted(t.Name)
		return nil
	}); err != nil {
		return newErr(err)
	}

	return &Runlinkat{}
}

// handle implements handler.handle.
func (t *Trename) handle(cs *connState) message {
	// Don't allow complex names.
	if err := checkSafeName(t.Name); err != nil {
		return newErr(err)
	}

	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	// Lookup the target.
	refTarget, ok := cs.LookupFID(t.Directory)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer refTarget.DecRef()

	if err := ref.safelyGlobal(func() (err error) {
		// Don't allow a root rename.
		if ref.isRoot() {
			return syscall.EINVAL
		}

		// Don't allow renaming deleting entries, or target non-directories.
		if ref.isDeleted() || refTarget.isDeleted() || !refTarget.mode.IsDir() {
			return syscall.EINVAL
		}

		// If the parent is deleted, but we not, something is seriously wrong.
		// It's fail to die at this point with an assertion failure.
		if ref.parent.isDeleted() {
			panic(fmt.Sprintf("parent %+v deleted, child %+v is not", ref.parent, ref))
		}

		// N.B. The rename operation is allowed to proceed on open files. It
		// does impact the state of its parent, but this is merely a sanity
		// check in any case, and the operation is safe. There may be other
		// files corresponding to the same path that are renamed anyways.

		// Check for the exact same file and short-circuit.
		oldName := ref.parent.pathNode.nameFor(ref)
		if ref.parent.pathNode == refTarget.pathNode && oldName == t.Name {
			return nil
		}

		// Call the rename method on the parent.
		if err := ref.parent.file.RenameAt(oldName, refTarget.file, t.Name); err != nil {
			return err
		}

		// Update the path tree.
		ref.parent.renameChildTo(oldName, refTarget, t.Name)
		return nil
	}); err != nil {
		return newErr(err)
	}

	return &Rrename{}
}

// handle implements handler.handle.
func (t *Treadlink) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	var target string
	if err := ref.safelyRead(func() (err error) {
		// Don't allow readlink on deleted files. There is no need to
		// check if this file is opened because symlinks cannot be
		// opened.
		if ref.isDeleted() || !ref.mode.IsSymlink() {
			return syscall.EINVAL
		}

		// Do the read.
		target, err = ref.file.Readlink()
		return err
	}); err != nil {
		return newErr(err)
	}

	return &Rreadlink{target}
}

// handle implements handler.handle.
func (t *Tread) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	// Constrain the size of the read buffer.
	if int(t.Count) > int(maximumLength) {
		return newErr(syscall.ENOBUFS)
	}

	var (
		data = make([]byte, t.Count)
		n    int
	)
	if err := ref.safelyRead(func() (err error) {
		// Has it been opened already?
		openFlags, opened := ref.OpenFlags()
		if !opened {
			return syscall.EINVAL
		}

		// Can it be read? Check permissions.
		if openFlags&OpenFlagsModeMask == WriteOnly {
			return syscall.EPERM
		}

		n, err = ref.file.ReadAt(data, t.Offset)
		return err
	}); err != nil && err != io.EOF {
		return newErr(err)
	}

	return &Rread{Data: data[:n]}
}

// handle implements handler.handle.
func (t *Twrite) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	var n int
	if err := ref.safelyRead(func() (err error) {
		// Has it been opened already?
		openFlags, opened := ref.OpenFlags()
		if !opened {
			return syscall.EINVAL
		}

		// Can it be written? Check permissions.
		if openFlags&OpenFlagsModeMask == ReadOnly {
			return syscall.EPERM
		}

		n, err = ref.file.WriteAt(t.Data, t.Offset)
		return err
	}); err != nil {
		return newErr(err)
	}

	return &Rwrite{Count: uint32(n)}
}

// handle implements handler.handle.
func (t *Tmknod) handle(cs *connState) message {
	rmknod, err := t.do(cs, NoUID)
	if err != nil {
		return newErr(err)
	}
	return rmknod
}

func (t *Tmknod) do(cs *connState, uid UID) (*Rmknod, error) {
	// Don't allow complex names.
	if err := checkSafeName(t.Name); err != nil {
		return nil, err
	}

	// Lookup the FID.
	ref, ok := cs.LookupFID(t.Directory)
	if !ok {
		return nil, syscall.EBADF
	}
	defer ref.DecRef()

	var qid QID
	if err := ref.safelyWrite(func() (err error) {
		// Don't allow mknod on deleted files.
		if ref.isDeleted() || !ref.mode.IsDir() {
			return syscall.EINVAL
		}

		// Not allowed on open directories.
		if _, opened := ref.OpenFlags(); opened {
			return syscall.EINVAL
		}

		// Do the mknod.
		qid, err = ref.file.Mknod(t.Name, t.Mode, t.Major, t.Minor, uid, t.GID)
		return err
	}); err != nil {
		return nil, err
	}

	return &Rmknod{QID: qid}, nil
}

// handle implements handler.handle.
func (t *Tmkdir) handle(cs *connState) message {
	rmkdir, err := t.do(cs, NoUID)
	if err != nil {
		return newErr(err)
	}
	return rmkdir
}

func (t *Tmkdir) do(cs *connState, uid UID) (*Rmkdir, error) {
	// Don't allow complex names.
	if err := checkSafeName(t.Name); err != nil {
		return nil, err
	}

	// Lookup the FID.
	ref, ok := cs.LookupFID(t.Directory)
	if !ok {
		return nil, syscall.EBADF
	}
	defer ref.DecRef()

	var qid QID
	if err := ref.safelyWrite(func() (err error) {
		// Don't allow mkdir on deleted files.
		if ref.isDeleted() || !ref.mode.IsDir() {
			return syscall.EINVAL
		}

		// Not allowed on open directories.
		if _, opened := ref.OpenFlags(); opened {
			return syscall.EINVAL
		}

		// Do the mkdir.
		qid, err = ref.file.Mkdir(t.Name, t.Permissions, uid, t.GID)
		return err
	}); err != nil {
		return nil, err
	}

	return &Rmkdir{QID: qid}, nil
}

// handle implements handler.handle.
func (t *Tgetattr) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	// We allow getattr on deleted files. Depending on the backing
	// implementation, it's possible that races exist that might allow
	// fetching attributes of other files. But we need to generally allow
	// refreshing attributes and this is a minor leak, if at all.

	var (
		qid   QID
		valid AttrMask
		attr  Attr
	)
	if err := ref.safelyRead(func() (err error) {
		qid, valid, attr, err = ref.file.GetAttr(t.AttrMask)
		return err
	}); err != nil {
		return newErr(err)
	}

	return &Rgetattr{QID: qid, Valid: valid, Attr: attr}
}

// handle implements handler.handle.
func (t *Tsetattr) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	if err := ref.safelyWrite(func() error {
		// We don't allow setattr on files that have been deleted.
		// This might be technically incorrect, as it's possible that
		// there were multiple links and you can still change the
		// corresponding inode information.
		if ref.isDeleted() {
			return syscall.EINVAL
		}

		// Set the attributes.
		return ref.file.SetAttr(t.Valid, t.SetAttr)
	}); err != nil {
		return newErr(err)
	}

	return &Rsetattr{}
}

// handle implements handler.handle.
func (t *Tallocate) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	if err := ref.safelyWrite(func() error {
		// Has it been opened already?
		openFlags, opened := ref.OpenFlags()
		if !opened {
			return syscall.EINVAL
		}

		// Can it be written? Check permissions.
		if openFlags&OpenFlagsModeMask == ReadOnly {
			return syscall.EBADF
		}

		// We don't allow allocate on files that have been deleted.
		if ref.isDeleted() {
			return syscall.EINVAL
		}

		return ref.file.Allocate(t.Mode, t.Offset, t.Length)
	}); err != nil {
		return newErr(err)
	}

	return &Rallocate{}
}

// handle implements handler.handle.
func (t *Txattrwalk) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	// We don't support extended attributes.
	return newErr(syscall.ENODATA)
}

// handle implements handler.handle.
func (t *Txattrcreate) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	// We don't support extended attributes.
	return newErr(syscall.ENOSYS)
}

// handle implements handler.handle.
func (t *Treaddir) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.Directory)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	var entries []Dirent
	if err := ref.safelyRead(func() (err error) {
		// Don't allow reading deleted directories.
		if ref.isDeleted() || !ref.mode.IsDir() {
			return syscall.EINVAL
		}

		// Has it been opened already?
		if _, opened := ref.OpenFlags(); !opened {
			return syscall.EINVAL
		}

		// Read the entries.
		entries, err = ref.file.Readdir(t.Offset, t.Count)
		if err != nil && err != io.EOF {
			return err
		}
		return nil
	}); err != nil {
		return newErr(err)
	}

	return &Rreaddir{Count: t.Count, Entries: entries}
}

// handle implements handler.handle.
func (t *Tfsync) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	if err := ref.safelyRead(func() (err error) {
		// Has it been opened already?
		if _, opened := ref.OpenFlags(); !opened {
			return syscall.EINVAL
		}

		// Perform the sync.
		return ref.file.FSync()
	}); err != nil {
		return newErr(err)
	}

	return &Rfsync{}
}

// handle implements handler.handle.
func (t *Tstatfs) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	st, err := ref.file.StatFS()
	if err != nil {
		return newErr(err)
	}

	return &Rstatfs{st}
}

// handle implements handler.handle.
func (t *Tflushf) handle(cs *connState) message {
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	if err := ref.safelyRead(ref.file.Flush); err != nil {
		return newErr(err)
	}

	return &Rflushf{}
}

// walkOne walks zero or one path elements.
//
// The slice passed as qids is append and returned.
func walkOne(qids []QID, from File, names []string, getattr bool) ([]QID, File, AttrMask, Attr, error) {
	if len(names) > 1 {
		// We require exactly zero or one elements.
		return nil, nil, AttrMask{}, Attr{}, syscall.EINVAL
	}
	var (
		localQIDs []QID
		sf        File
		valid     AttrMask
		attr      Attr
		err       error
	)
	switch {
	case getattr:
		localQIDs, sf, valid, attr, err = from.WalkGetAttr(names)
		// Can't put fallthrough in the if because Go.
		if err != syscall.ENOSYS {
			break
		}
		fallthrough
	default:
		localQIDs, sf, err = from.Walk(names)
		if err != nil {
			// No way to walk this element.
			break
		}
		if getattr {
			_, valid, attr, err = sf.GetAttr(AttrMaskAll())
			if err != nil {
				// Don't leak the file.
				sf.Close()
			}
		}
	}
	if err != nil {
		// Error walking, don't return anything.
		return nil, nil, AttrMask{}, Attr{}, err
	}
	if len(localQIDs) != 1 {
		// Expected a single QID.
		sf.Close()
		return nil, nil, AttrMask{}, Attr{}, syscall.EINVAL
	}
	return append(qids, localQIDs...), sf, valid, attr, nil
}

// doWalk walks from a given fidRef.
//
// This enforces that all intermediate nodes are walkable (directories). The
// fidRef returned (newRef) has a reference associated with it that is now
// owned by the caller and must be handled appropriately.
func doWalk(cs *connState, ref *fidRef, names []string, getattr bool) (qids []QID, newRef *fidRef, valid AttrMask, attr Attr, err error) {
	// Check the names.
	for _, name := range names {
		err = checkSafeName(name)
		if err != nil {
			return
		}
	}

	// Has it been opened already?
	if _, opened := ref.OpenFlags(); opened {
		err = syscall.EBUSY
		return
	}

	// Is this an empty list? Handle specially. We don't actually need to
	// validate anything since this is always permitted.
	if len(names) == 0 {
		var sf File // Temporary.
		if err := ref.maybeParent().safelyRead(func() (err error) {
			// Clone the single element.
			qids, sf, valid, attr, err = walkOne(nil, ref.file, nil, getattr)
			if err != nil {
				return err
			}

			newRef = &fidRef{
				server:   cs.server,
				parent:   ref.parent,
				file:     sf,
				mode:     ref.mode,
				pathNode: ref.pathNode,

				// For the clone case, the cloned fid must
				// preserve the deleted property of the
				// original FID.
				deleted: ref.deleted,
			}
			if !ref.isRoot() {
				if !newRef.isDeleted() {
					// Add only if a non-root node; the same node.
					ref.parent.pathNode.addChild(newRef, ref.parent.pathNode.nameFor(ref))
				}
				ref.parent.IncRef() // Acquire parent reference.
			}
			// doWalk returns a reference.
			newRef.IncRef()
			return nil
		}); err != nil {
			return nil, nil, AttrMask{}, Attr{}, err
		}
		// Do not return the new QID.
		return nil, newRef, valid, attr, nil
	}

	// Do the walk, one element at a time.
	walkRef := ref
	walkRef.IncRef()
	for i := 0; i < len(names); i++ {
		// We won't allow beyond past symlinks; stop here if this isn't
		// a proper directory and we have additional paths to walk.
		if !walkRef.mode.IsDir() {
			walkRef.DecRef() // Drop walk reference; no lock required.
			return nil, nil, AttrMask{}, Attr{}, syscall.EINVAL
		}

		var sf File // Temporary.
		if err := walkRef.safelyRead(func() (err error) {
			// Pass getattr = true to walkOne since we need the file type for
			// newRef.
			qids, sf, valid, attr, err = walkOne(qids, walkRef.file, names[i:i+1], true)
			if err != nil {
				return err
			}

			// Note that we don't need to acquire a lock on any of
			// these individual instances. That's because they are
			// not actually addressable via a FID. They are
			// anonymous. They exist in the tree for tracking
			// purposes.
			newRef := &fidRef{
				server:   cs.server,
				parent:   walkRef,
				file:     sf,
				mode:     attr.Mode.FileType(),
				pathNode: walkRef.pathNode.pathNodeFor(names[i]),
			}
			walkRef.pathNode.addChild(newRef, names[i])
			// We allow our walk reference to become the new parent
			// reference here and so we don't IncRef. Instead, just
			// set walkRef to the newRef above and acquire a new
			// walk reference.
			walkRef = newRef
			walkRef.IncRef()
			return nil
		}); err != nil {
			walkRef.DecRef() // Drop the old walkRef.
			return nil, nil, AttrMask{}, Attr{}, err
		}
	}

	// Success.
	return qids, walkRef, valid, attr, nil
}

// handle implements handler.handle.
func (t *Twalk) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	// Do the walk.
	qids, newRef, _, _, err := doWalk(cs, ref, t.Names, false)
	if err != nil {
		return newErr(err)
	}
	defer newRef.DecRef()

	// Install the new FID.
	cs.InsertFID(t.NewFID, newRef)
	return &Rwalk{QIDs: qids}
}

// handle implements handler.handle.
func (t *Twalkgetattr) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	// Do the walk.
	qids, newRef, valid, attr, err := doWalk(cs, ref, t.Names, true)
	if err != nil {
		return newErr(err)
	}
	defer newRef.DecRef()

	// Install the new FID.
	cs.InsertFID(t.NewFID, newRef)
	return &Rwalkgetattr{QIDs: qids, Valid: valid, Attr: attr}
}

// handle implements handler.handle.
func (t *Tucreate) handle(cs *connState) message {
	rlcreate, err := t.Tlcreate.do(cs, t.UID)
	if err != nil {
		return newErr(err)
	}
	return &Rucreate{*rlcreate}
}

// handle implements handler.handle.
func (t *Tumkdir) handle(cs *connState) message {
	rmkdir, err := t.Tmkdir.do(cs, t.UID)
	if err != nil {
		return newErr(err)
	}
	return &Rumkdir{*rmkdir}
}

// handle implements handler.handle.
func (t *Tusymlink) handle(cs *connState) message {
	rsymlink, err := t.Tsymlink.do(cs, t.UID)
	if err != nil {
		return newErr(err)
	}
	return &Rusymlink{*rsymlink}
}

// handle implements handler.handle.
func (t *Tumknod) handle(cs *connState) message {
	rmknod, err := t.Tmknod.do(cs, t.UID)
	if err != nil {
		return newErr(err)
	}
	return &Rumknod{*rmknod}
}

// handle implements handler.handle.
func (t *Tlconnect) handle(cs *connState) message {
	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	var osFile *fd.FD
	if err := ref.safelyRead(func() (err error) {
		// Don't allow connecting to deleted files.
		if ref.isDeleted() || !ref.mode.IsSocket() {
			return syscall.EINVAL
		}

		// Do the connect.
		osFile, err = ref.file.Connect(t.Flags)
		return err
	}); err != nil {
		return newErr(err)
	}

	rlconnect := &Rlconnect{}
	rlconnect.SetFilePayload(osFile)
	return rlconnect
}

// handle implements handler.handle.
func (t *Tchannel) handle(cs *connState) message {
	// Ensure that channels are enabled.
	if err := cs.initializeChannels(); err != nil {
		return newErr(err)
	}

	// Lookup the given channel.
	ch := cs.lookupChannel(t.ID)
	if ch == nil {
		return newErr(syscall.ENOSYS)
	}

	// Return the payload. Note that we need to duplicate the file
	// descriptor for the channel allocator, because sending is a
	// destructive operation between sendRecvLegacy (and now the newer
	// channel send operations). Same goes for the client FD.
	rchannel := &Rchannel{
		Offset: uint64(ch.desc.Offset),
		Length: uint64(ch.desc.Length),
	}
	switch t.Control {
	case 0:
		// Open the main data channel.
		mfd, err := syscall.Dup(int(cs.channelAlloc.FD()))
		if err != nil {
			return newErr(err)
		}
		rchannel.SetFilePayload(fd.New(mfd))
	case 1:
		cfd, err := syscall.Dup(ch.client.FD())
		if err != nil {
			return newErr(err)
		}
		rchannel.SetFilePayload(fd.New(cfd))
	default:
		return newErr(syscall.EINVAL)
	}
	return rchannel
}
