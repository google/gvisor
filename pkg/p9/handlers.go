// Copyright 2018 Google LLC
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
	"io"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/log"
)

// newErr returns a new error message from an error.
func newErr(err error) *Rlerror {
	switch e := err.(type) {
	case syscall.Errno:
		return &Rlerror{Error: uint32(e)}
	case *os.PathError:
		return newErr(e.Err)
	case *os.SyscallError:
		return newErr(e.Err)
	default:
		log.Warningf("unknown error: %v", err)
		return &Rlerror{Error: uint32(syscall.EIO)}
	}
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

// isSafeName returns true iff the name does not contain directory characters.
//
// We permit walks only on safe names and store the sequence of paths used for
// any given walk in each FID. (This is immutable.) We use this to mark
// relevant FIDs as moved when a successful rename occurs.
func isSafeName(name string) bool {
	return name != "" && !strings.Contains(name, "/") && name != "." && name != ".."
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

	// "The remove request asks the file server both to remove the file
	// represented by fid and to clunk the fid, even if the remove fails."
	//
	// "It is correct to consider remove to be a clunk with the side effect
	// of removing the file if permissions allow."
	// https://swtch.com/plan9port/man/man9/remove.html
	err := ref.file.Remove()

	// Clunk the FID regardless of Remove error.
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
	_, valid, attr, err := sf.GetAttr(AttrMaskAll())
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
		file:     sf,
		refs:     1,
		walkable: attr.Mode.IsDir(),
	}
	defer root.DecRef()

	// Attach the root?
	if len(t.Auth.AttachName) == 0 {
		cs.InsertFID(t.FID, root)
		return &Rattach{}
	}

	// We want the same traversal checks to apply on attach, so always
	// attach at the root and use the regular walk paths.
	names := strings.Split(t.Auth.AttachName, "/")
	_, target, _, attr, err := doWalk(cs, root, names)
	if err != nil {
		return newErr(err)
	}

	// Insert the FID.
	cs.InsertFID(t.FID, &fidRef{
		file:     target,
		walkable: attr.Mode.IsDir(),
	})

	return &Rattach{}
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
	if ref.opened {
		return newErr(syscall.EINVAL)
	}

	// Do the open.
	osFile, qid, ioUnit, err := ref.file.Open(t.Flags)
	if err != nil {
		return newErr(err)
	}

	// Mark file as opened and set open mode.
	ref.opened = true
	ref.openFlags = t.Flags

	return &Rlopen{QID: qid, IoUnit: ioUnit, File: osFile}
}

func (t *Tlcreate) do(cs *connState, uid UID) (*Rlcreate, error) {
	// Don't allow complex names.
	if !isSafeName(t.Name) {
		return nil, syscall.EINVAL
	}

	// Lookup the FID.
	ref, ok := cs.LookupFID(t.FID)
	if !ok {
		return nil, syscall.EBADF
	}
	defer ref.DecRef()

	// Do the create.
	osFile, nsf, qid, ioUnit, err := ref.file.Create(t.Name, t.OpenFlags, t.Permissions, uid, t.GID)
	if err != nil {
		return nil, err
	}

	// Replace the FID reference.
	//
	// The new file will be opened already.
	cs.InsertFID(t.FID, &fidRef{
		file:      nsf,
		opened:    true,
		openFlags: t.OpenFlags,
	})

	return &Rlcreate{Rlopen: Rlopen{QID: qid, IoUnit: ioUnit, File: osFile}}, nil
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
	if !isSafeName(t.Name) {
		return nil, syscall.EINVAL
	}

	// Lookup the FID.
	ref, ok := cs.LookupFID(t.Directory)
	if !ok {
		return nil, syscall.EBADF
	}
	defer ref.DecRef()

	// Do the symlink.
	qid, err := ref.file.Symlink(t.Target, t.Name, uid, t.GID)
	if err != nil {
		return nil, err
	}

	return &Rsymlink{QID: qid}, nil
}

// handle implements handler.handle.
func (t *Tlink) handle(cs *connState) message {
	// Don't allow complex names.
	if !isSafeName(t.Name) {
		return newErr(syscall.EINVAL)
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

	// Do the link.
	if err := ref.file.Link(refTarget.file, t.Name); err != nil {
		return newErr(err)
	}

	return &Rlink{}
}

// handle implements handler.handle.
func (t *Trenameat) handle(cs *connState) message {
	// Don't allow complex names.
	if !isSafeName(t.OldName) || !isSafeName(t.NewName) {
		return newErr(syscall.EINVAL)
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

	// Do the rename.
	if err := ref.file.RenameAt(t.OldName, refTarget.file, t.NewName); err != nil {
		return newErr(err)
	}

	return &Rrenameat{}
}

// handle implements handler.handle.
func (t *Tunlinkat) handle(cs *connState) message {
	// Don't allow complex names.
	if !isSafeName(t.Name) {
		return newErr(syscall.EINVAL)
	}

	// Lookup the FID.
	ref, ok := cs.LookupFID(t.Directory)
	if !ok {
		return newErr(syscall.EBADF)
	}
	defer ref.DecRef()

	// Do the unlink.
	if err := ref.file.UnlinkAt(t.Name, t.Flags); err != nil {
		return newErr(err)
	}

	return &Runlinkat{}
}

// handle implements handler.handle.
func (t *Trename) handle(cs *connState) message {
	// Don't allow complex names.
	if !isSafeName(t.Name) {
		return newErr(syscall.EINVAL)
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

	// Call the rename method.
	if err := ref.file.Rename(refTarget.file, t.Name); err != nil {
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

	// Do the read.
	target, err := ref.file.Readlink()
	if err != nil {
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

	// Has it been opened already?
	openFlags, opened := ref.OpenFlags()
	if !opened {
		return newErr(syscall.EINVAL)
	}

	// Can it be read? Check permissions.
	if openFlags&OpenFlagsModeMask == WriteOnly {
		return newErr(syscall.EPERM)
	}

	// Constrain the size of the read buffer.
	if int(t.Count) > int(maximumLength) {
		return newErr(syscall.ENOBUFS)
	}

	// Do the read.
	data := make([]byte, t.Count)
	n, err := ref.file.ReadAt(data, t.Offset)
	if err != nil && err != io.EOF {
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

	// Has it been opened already?
	openFlags, opened := ref.OpenFlags()
	if !opened {
		return newErr(syscall.EINVAL)
	}

	// Can it be write? Check permissions.
	if openFlags&OpenFlagsModeMask == ReadOnly {
		return newErr(syscall.EPERM)
	}

	// Do the write.
	n, err := ref.file.WriteAt(t.Data, t.Offset)
	if err != nil {
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
	if !isSafeName(t.Name) {
		return nil, syscall.EINVAL
	}

	// Lookup the FID.
	ref, ok := cs.LookupFID(t.Directory)
	if !ok {
		return nil, syscall.EBADF
	}
	defer ref.DecRef()

	// Do the mknod.
	qid, err := ref.file.Mknod(t.Name, t.Permissions, t.Major, t.Minor, uid, t.GID)
	if err != nil {
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
	if !isSafeName(t.Name) {
		return nil, syscall.EINVAL
	}

	// Lookup the FID.
	ref, ok := cs.LookupFID(t.Directory)
	if !ok {
		return nil, syscall.EBADF
	}
	defer ref.DecRef()

	// Do the mkdir.
	qid, err := ref.file.Mkdir(t.Name, t.Permissions, uid, t.GID)
	if err != nil {
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

	// Get attributes.
	qid, valid, attr, err := ref.file.GetAttr(t.AttrMask)
	if err != nil {
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

	// Set attributes.
	if err := ref.file.SetAttr(t.Valid, t.SetAttr); err != nil {
		return newErr(err)
	}

	return &Rsetattr{}
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

	// Has it been opened already?
	if _, opened := ref.OpenFlags(); !opened {
		return newErr(syscall.EINVAL)
	}

	// Read the entries.
	entries, err := ref.file.Readdir(t.Offset, t.Count)
	if err != nil && err != io.EOF {
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

	// Has it been opened already?
	if _, opened := ref.OpenFlags(); !opened {
		return newErr(syscall.EINVAL)
	}

	err := ref.file.FSync()
	if err != nil {
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

	if err := ref.file.Flush(); err != nil {
		return newErr(err)
	}

	return &Rflushf{}
}

// walkOne walks zero or one path elements.
//
// The slice passed as qids is append and returned.
func walkOne(qids []QID, from File, names []string) ([]QID, File, AttrMask, Attr, error) {
	if len(names) > 1 {
		// We require exactly zero or one elements.
		return nil, nil, AttrMask{}, Attr{}, syscall.EINVAL
	}
	var localQIDs []QID
	localQIDs, sf, valid, attr, err := from.WalkGetAttr(names)
	if err == syscall.ENOSYS {
		localQIDs, sf, err = from.Walk(names)
		if err != nil {
			// No way to walk this element.
			return nil, nil, AttrMask{}, Attr{}, err
		}
		// Need a manual getattr.
		_, valid, attr, err = sf.GetAttr(AttrMaskAll())
		if err != nil {
			// Don't leak the file.
			sf.Close()
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
// This enforces that all intermediate nodes are walkable (directories).
func doWalk(cs *connState, ref *fidRef, names []string) (qids []QID, sf File, valid AttrMask, attr Attr, err error) {
	// Check the names.
	for _, name := range names {
		if !isSafeName(name) {
			err = syscall.EINVAL
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
		return walkOne(nil, ref.file, nil)
	}

	// Is it walkable?
	if !ref.walkable {
		err = syscall.EINVAL
		return
	}

	from := ref.file // Start at the passed ref.

	// Do the walk, one element at a time.
	for i := 0; i < len(names); i++ {
		qids, sf, valid, attr, err = walkOne(qids, from, names[i:i+1])

		// Close the intermediate file. Note that we don't close the
		// first file because in that case we are walking from the
		// existing reference.
		if i > 0 {
			from.Close()
		}
		from = sf // Use the new file.

		// Was there an error walking?
		if err != nil {
			return nil, nil, AttrMask{}, Attr{}, err
		}

		// We won't allow beyond past symlinks; stop here if this isn't
		// a proper directory and we have additional paths to walk.
		if !valid.Mode || (!attr.Mode.IsDir() && i < len(names)-1) {
			from.Close() // Not using the file object.
			return nil, nil, AttrMask{}, Attr{}, syscall.EINVAL
		}
	}

	// Success.
	return qids, sf, valid, attr, nil
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
	qids, sf, _, attr, err := doWalk(cs, ref, t.Names)
	if err != nil {
		return newErr(err)
	}

	// Install the new FID.
	cs.InsertFID(t.NewFID, &fidRef{
		file:     sf,
		walkable: attr.Mode.IsDir(),
	})

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
	qids, sf, valid, attr, err := doWalk(cs, ref, t.Names)
	if err != nil {
		return newErr(err)
	}

	// Install the new FID.
	cs.InsertFID(t.NewFID, &fidRef{
		file:     sf,
		walkable: attr.Mode.IsDir(),
	})

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

	// Do the connect.
	osFile, err := ref.file.Connect(t.Flags)
	if err != nil {
		return newErr(err)
	}

	return &Rlconnect{File: osFile}
}
