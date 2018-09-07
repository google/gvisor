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

package p9

import (
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/fd"
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
// Functions below MUST return syscall.Errno values.
// TODO: Enforce that with the type.
//
// These must be implemented in all circumstances.
type File interface {
	// Walk walks to the path components given in names.
	//
	// Walk returns QIDs in the same order that the names were passed in.
	//
	// An empty list of arguments should return a copy of the current file.
	Walk(names []string) ([]QID, File, error)

	// StatFS returns information about the file system associated with
	// this file.
	StatFS() (FSStat, error)

	// GetAttr returns attributes of this node.
	GetAttr(req AttrMask) (QID, AttrMask, Attr, error)

	// SetAttr sets attributes on this node.
	SetAttr(valid SetAttrMask, attr SetAttr) error

	// Remove removes the file.
	//
	// This is deprecated in favor of UnlinkAt below.
	Remove() error

	// Rename renames the file.
	Rename(directory File, name string) error

	// Close is called when all references are dropped on the server side,
	// and Close should be called by the client to drop all references.
	//
	// For server-side implementations of Close, the error is ignored.
	//
	// Close must be called even when Open has not been called.
	Close() error

	// Open is called prior to using read/write.
	//
	// The *fd.FD may be nil. If an *fd.FD is provided, ownership now
	// belongs to the caller and the FD must be non-blocking.
	//
	// If Open returns a non-nil *fd.FD, it should do so for all possible
	// OpenFlags. If Open returns a nil *fd.FD, it should similarly return
	// a nil *fd.FD for all possible OpenFlags.
	//
	// This can be assumed to be one-shot only.
	Open(mode OpenFlags) (*fd.FD, QID, uint32, error)

	// Read reads from this file.
	//
	// This may return io.EOF in addition to syscall.Errno values.
	//
	// Preconditions: Open has been called and returned success.
	ReadAt(p []byte, offset uint64) (int, error)

	// Write writes to this file.
	//
	// This may return io.EOF in addition to syscall.Errno values.
	//
	// Preconditions: Open has been called and returned success.
	WriteAt(p []byte, offset uint64) (int, error)

	// FSync syncs this node.
	//
	// Preconditions: Open has been called and returned success.
	FSync() error

	// Create creates a new regular file and opens it according to the
	// flags given.
	//
	// See p9.File.Open for a description of *fd.FD.
	Create(name string, flags OpenFlags, permissions FileMode, uid UID, gid GID) (*fd.FD, File, QID, uint32, error)

	// Mkdir creates a subdirectory.
	Mkdir(name string, permissions FileMode, uid UID, gid GID) (QID, error)

	// Symlink makes a new symbolic link.
	Symlink(oldname string, newname string, uid UID, gid GID) (QID, error)

	// Link makes a new hard link.
	Link(target File, newname string) error

	// Mknod makes a new device node.
	Mknod(name string, permissions FileMode, major uint32, minor uint32, uid UID, gid GID) (QID, error)

	// RenameAt renames a given file to a new name in a potentially new
	// directory.
	//
	// oldname must be a name relative to this file, which must be a
	// directory. newname is a name relative to newdir.
	//
	// This is deprecated in favor of Rename.
	RenameAt(oldname string, newdir File, newname string) error

	// UnlinkAt the given named file.
	//
	// name must be a file relative to this directory.
	//
	// Flags are implementation-specific (e.g. O_DIRECTORY), but are
	// generally Linux unlinkat(2) flags.
	UnlinkAt(name string, flags uint32) error

	// Readdir reads directory entries.
	//
	// This may return io.EOF in addition to syscall.Errno values.
	//
	// Preconditions: Open has been called and returned success.
	Readdir(offset uint64, count uint32) ([]Dirent, error)

	// Readlink reads the link target.
	Readlink() (string, error)

	// Flush is called prior to Close.
	//
	// Whereas Close drops all references to the file, Flush cleans up the
	// file state. Behavior is implementation-specific.
	//
	// Flush is not related to flush(9p).  Flush is an extension to 9P2000.L,
	// see version.go.
	Flush() error

	// WalkGetAttr walks to the next file and returns its maximal set of
	// attributes.
	//
	// Server-side p9.Files may return syscall.ENOSYS to indicate that Walk
	// and GetAttr should be used separately to satisfy this request.
	WalkGetAttr([]string) ([]QID, File, AttrMask, Attr, error)

	// Connect establishes a new host-socket backed connection with a
	// socket. A File does not need to be opened before it can be connected
	// and it can be connected to multiple times resulting in a unique
	// *fd.FD each time. In addition, the lifetime of the *fd.FD is
	// independent from the lifetime of the p9.File and must be managed by
	// the caller.
	//
	// The returned FD must be non-blocking.
	//
	// flags indicates the requested type of socket.
	Connect(flags ConnectFlags) (*fd.FD, error)
}

// DefaultWalkGetAttr implements File.WalkGetAttr to return ENOSYS for server-side Files.
type DefaultWalkGetAttr struct{}

// WalkGetAttr implements File.WalkGetAttr.
func (DefaultWalkGetAttr) WalkGetAttr([]string) ([]QID, File, AttrMask, Attr, error) {
	return nil, nil, AttrMask{}, Attr{}, syscall.ENOSYS
}
