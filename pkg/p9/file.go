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
	"syscall"

	"gvisor.dev/gvisor/pkg/fd"
)

// Attacher is provided by the server.
type Attacher interface {
	// Attach returns a new File.
	//
	// The client-side attach will be translate to a series of walks from
	// the file returned by this Attach call.
	Attach() (File, error)
}

// File is a set of operations corresponding to a single node.
//
// Note that on the server side, the server logic places constraints on
// concurrent operations to make things easier. This may reduce the need for
// complex, error-prone locking and logic in the backend. These are documented
// for each method.
//
// There are three different types of guarantees provided:
//
// none: There is no concurrency guarantee. The method may be invoked
// concurrently with any other method on any other file.
//
// read: The method is guaranteed to be exclusive of any write or global
// operation that is mutating the state of the directory tree starting at this
// node. For example, this means creating new files, symlinks, directories or
// renaming a directory entry (or renaming in to this target), but the method
// may be called concurrently with other read methods.
//
// write: The method is guaranteed to be exclusive of any read, write or global
// operation that is mutating the state of the directory tree starting at this
// node, as described in read above. There may however, be other write
// operations executing concurrently on other components in the directory tree.
//
// global: The method is guaranteed to be exclusive of any read, write or
// global operation.
type File interface {
	// Walk walks to the path components given in names.
	//
	// Walk returns QIDs in the same order that the names were passed in.
	//
	// An empty list of arguments should return a copy of the current file.
	//
	// On the server, Walk has a read concurrency guarantee.
	Walk(names []string) ([]QID, File, error)

	// WalkGetAttr walks to the next file and returns its maximal set of
	// attributes.
	//
	// Server-side p9.Files may return syscall.ENOSYS to indicate that Walk
	// and GetAttr should be used separately to satisfy this request.
	//
	// On the server, WalkGetAttr has a read concurrency guarantee.
	WalkGetAttr([]string) ([]QID, File, AttrMask, Attr, error)

	// StatFS returns information about the file system associated with
	// this file.
	//
	// On the server, StatFS has no concurrency guarantee.
	StatFS() (FSStat, error)

	// GetAttr returns attributes of this node.
	//
	// On the server, GetAttr has a read concurrency guarantee.
	GetAttr(req AttrMask) (QID, AttrMask, Attr, error)

	// SetAttr sets attributes on this node.
	//
	// On the server, SetAttr has a write concurrency guarantee.
	SetAttr(valid SetAttrMask, attr SetAttr) error

	// Allocate allows the caller to directly manipulate the allocated disk space
	// for the file. See fallocate(2) for more details.
	Allocate(mode AllocateMode, offset, length uint64) error

	// Close is called when all references are dropped on the server side,
	// and Close should be called by the client to drop all references.
	//
	// For server-side implementations of Close, the error is ignored.
	//
	// Close must be called even when Open has not been called.
	//
	// On the server, Close has no concurrency guarantee.
	Close() error

	// Open must be called prior to using Read, Write or Readdir. Once Open
	// is called, some operations, such as Walk, will no longer work.
	//
	// On the client, Open should be called only once. The fd return is
	// optional, and may be nil.
	//
	// On the server, Open has a read concurrency guarantee. If an *fd.FD
	// is provided, ownership now belongs to the caller. Open is guaranteed
	// to be called only once.
	//
	// N.B. The server must resolve any lazy paths when open is called.
	// After this point, read and write may be called on files with no
	// deletion check, so resolving in the data path is not viable.
	Open(flags OpenFlags) (*fd.FD, QID, uint32, error)

	// Read reads from this file. Open must be called first.
	//
	// This may return io.EOF in addition to syscall.Errno values.
	//
	// On the server, ReadAt has a read concurrency guarantee. See Open for
	// additional requirements regarding lazy path resolution.
	ReadAt(p []byte, offset uint64) (int, error)

	// Write writes to this file. Open must be called first.
	//
	// This may return io.EOF in addition to syscall.Errno values.
	//
	// On the server, WriteAt has a read concurrency guarantee. See Open
	// for additional requirements regarding lazy path resolution.
	WriteAt(p []byte, offset uint64) (int, error)

	// FSync syncs this node. Open must be called first.
	//
	// On the server, FSync has a read concurrency guarantee.
	FSync() error

	// Create creates a new regular file and opens it according to the
	// flags given. This file is already Open.
	//
	// N.B. On the client, the returned file is a reference to the current
	// file, which now represents the created file. This is not the case on
	// the server. These semantics are very subtle and can easily lead to
	// bugs, but are a consequence of the 9P create operation.
	//
	// See p9.File.Open for a description of *fd.FD.
	//
	// On the server, Create has a write concurrency guarantee.
	Create(name string, flags OpenFlags, permissions FileMode, uid UID, gid GID) (*fd.FD, File, QID, uint32, error)

	// Mkdir creates a subdirectory.
	//
	// On the server, Mkdir has a write concurrency guarantee.
	Mkdir(name string, permissions FileMode, uid UID, gid GID) (QID, error)

	// Symlink makes a new symbolic link.
	//
	// On the server, Symlink has a write concurrency guarantee.
	Symlink(oldName string, newName string, uid UID, gid GID) (QID, error)

	// Link makes a new hard link.
	//
	// On the server, Link has a write concurrency guarantee.
	Link(target File, newName string) error

	// Mknod makes a new device node.
	//
	// On the server, Mknod has a write concurrency guarantee.
	Mknod(name string, mode FileMode, major uint32, minor uint32, uid UID, gid GID) (QID, error)

	// Rename renames the file.
	//
	// Rename will never be called on the server, and RenameAt will always
	// be used instead.
	Rename(newDir File, newName string) error

	// RenameAt renames a given file to a new name in a potentially new
	// directory.
	//
	// oldName must be a name relative to this file, which must be a
	// directory. newName is a name relative to newDir.
	//
	// On the server, RenameAt has a global concurrency guarantee.
	RenameAt(oldName string, newDir File, newName string) error

	// UnlinkAt the given named file.
	//
	// name must be a file relative to this directory.
	//
	// Flags are implementation-specific (e.g. O_DIRECTORY), but are
	// generally Linux unlinkat(2) flags.
	//
	// On the server, UnlinkAt has a write concurrency guarantee.
	UnlinkAt(name string, flags uint32) error

	// Readdir reads directory entries.
	//
	// This may return io.EOF in addition to syscall.Errno values.
	//
	// On the server, Readdir has a read concurrency guarantee.
	Readdir(offset uint64, count uint32) ([]Dirent, error)

	// Readlink reads the link target.
	//
	// On the server, Readlink has a read concurrency guarantee.
	Readlink() (string, error)

	// Flush is called prior to Close.
	//
	// Whereas Close drops all references to the file, Flush cleans up the
	// file state. Behavior is implementation-specific.
	//
	// Flush is not related to flush(9p). Flush is an extension to 9P2000.L,
	// see version.go.
	//
	// On the server, Flush has a read concurrency guarantee.
	Flush() error

	// Connect establishes a new host-socket backed connection with a
	// socket. A File does not need to be opened before it can be connected
	// and it can be connected to multiple times resulting in a unique
	// *fd.FD each time. In addition, the lifetime of the *fd.FD is
	// independent from the lifetime of the p9.File and must be managed by
	// the caller.
	//
	// The returned FD must be non-blocking.
	//
	// Flags indicates the requested type of socket.
	//
	// On the server, Connect has a read concurrency guarantee.
	Connect(flags ConnectFlags) (*fd.FD, error)

	// Renamed is called when this node is renamed.
	//
	// This may not fail. The file will hold a reference to its parent
	// within the p9 package, and is therefore safe to use for the lifetime
	// of this File (until Close is called).
	//
	// This method should not be called by clients, who should use the
	// relevant Rename methods. (Although the method will be a no-op.)
	//
	// On the server, Renamed has a global concurrency guarantee.
	Renamed(newDir File, newName string)
}

// DefaultWalkGetAttr implements File.WalkGetAttr to return ENOSYS for server-side Files.
type DefaultWalkGetAttr struct{}

// WalkGetAttr implements File.WalkGetAttr.
func (DefaultWalkGetAttr) WalkGetAttr([]string) ([]QID, File, AttrMask, Attr, error) {
	return nil, nil, AttrMask{}, Attr{}, syscall.ENOSYS
}
