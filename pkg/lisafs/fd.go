// Copyright 2021 The gVisor Authors.
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

package lisafs

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/refsvfs2"
	"gvisor.dev/gvisor/pkg/sync"
)

// FDID (file descriptor identifier) is used to identify FDs on a connection.
// Each connection has its own FDID namespace.
//
// +marshal slice:FDIDSlice
type FDID uint32

// InvalidFDID represents an invalid FDID.
const InvalidFDID FDID = 0

// Ok returns true if f is a valid FDID.
func (f FDID) Ok() bool {
	return f != InvalidFDID
}

// genericFD can represent a ControlFD or OpenFD.
type genericFD interface {
	refsvfs2.RefCounter
}

// A ControlFD is the gateway to the backing filesystem tree node. It is an
// unusual concept. This exists to provide a safe way to do path-based
// operations on the file. It performs operations that can modify the
// filesystem tree and synchronizes these operations. See ControlFDImpl for
// supported operations.
//
// It is not an inode, because multiple control FDs are allowed to exist on the
// same file. It is not a file descriptor because it is not tied to any access
// mode, i.e. a control FD can change its access mode based on the operation
// being performed.
//
// Reference Model:
// * When a control FD is created, the connection takes a ref on it which
//   represents the client's ref on the FD.
// * The client can drop its ref via the Close RPC which will in turn make the
//   connection drop its ref.
// * Each control FD holds a ref on its parent for its entire life time.
type ControlFD struct {
	controlFDRefs
	controlFDEntry

	// parent is the parent directory FD containing the file this FD represents.
	// A ControlFD holds a ref on parent for its entire lifetime. If this FD
	// represents the root, then parent is nil. parent may be a control FD from
	// another connection (another mount point). parent is protected by the
	// backing server's rename mutex.
	parent *ControlFD

	// name is the file path's last component name. If this FD represents the
	// root directory, then name is the mount path. name is protected by the
	// backing server's rename mutex.
	name string

	// children is a linked list of all children control FDs. As per reference
	// model, all children hold a ref on this FD.
	// children is protected by childrenMu and server's rename mutex. To have
	// mutual exclusion, it is sufficient to:
	// * Hold rename mutex for reading and lock childrenMu. OR
	// * Or hold rename mutex for writing.
	childrenMu sync.Mutex
	children   controlFDList

	// openFDs is a linked list of all FDs opened on this FD. As per reference
	// model, all open FDs hold a ref on this FD.
	openFDsMu sync.RWMutex
	openFDs   openFDList

	// All the following fields are immutable.

	// id is the unique FD identifier which identifies this FD on its connection.
	id FDID

	// conn is the backing connection owning this FD.
	conn *Connection

	// ftype is the file type of the backing inode. ftype.FileType() == ftype.
	ftype linux.FileMode

	// impl is the control FD implementation which embeds this struct. It
	// contains all the implementation specific details.
	impl ControlFDImpl
}

var _ genericFD = (*ControlFD)(nil)

// DecRef implements refsvfs2.RefCounter.DecRef. Note that the context
// parameter should never be used. It exists solely to comply with the
// refsvfs2.RefCounter interface.
func (fd *ControlFD) DecRef(context.Context) {
	fd.controlFDRefs.DecRef(func() {
		if fd.parent != nil {
			fd.conn.server.RenameMu.RLock()
			fd.parent.childrenMu.Lock()
			fd.parent.children.Remove(fd)
			fd.parent.childrenMu.Unlock()
			fd.conn.server.RenameMu.RUnlock()
			fd.parent.DecRef(nil) // Drop the ref on the parent.
		}
		fd.impl.Close(fd.conn)
	})
}

// DecRefLocked is the same as DecRef except the added precondition.
//
// Precondition: server's rename mutex must be at least read locked.
func (fd *ControlFD) DecRefLocked() {
	fd.controlFDRefs.DecRef(func() {
		fd.clearParentLocked()
		fd.impl.Close(fd.conn)
	})
}

// Precondition: server's rename mutex must be at least read locked.
func (fd *ControlFD) clearParentLocked() {
	if fd.parent == nil {
		return
	}
	fd.parent.childrenMu.Lock()
	fd.parent.children.Remove(fd)
	fd.parent.childrenMu.Unlock()
	fd.parent.DecRefLocked() // Drop the ref on the parent.
}

// Init must be called before first use of fd. It inserts fd into the
// filesystem tree.
//
// Precondition: server's rename mutex must be at least read locked.
func (fd *ControlFD) Init(c *Connection, parent *ControlFD, name string, mode linux.FileMode, impl ControlFDImpl) {
	// Initialize fd with 1 ref which is transferred to c via c.insertFD().
	fd.controlFDRefs.InitRefs()
	fd.conn = c
	fd.id = c.insertFD(fd)
	fd.name = name
	fd.ftype = mode.FileType()
	fd.impl = impl
	fd.setParentLocked(parent)
}

// Precondition: server's rename mutex must be at least read locked.
func (fd *ControlFD) setParentLocked(parent *ControlFD) {
	fd.parent = parent
	if parent != nil {
		parent.IncRef() // Hold a ref on parent.
		parent.childrenMu.Lock()
		parent.children.PushBack(fd)
		parent.childrenMu.Unlock()
	}
}

// FileType returns the file mode only containing the file type bits.
func (fd *ControlFD) FileType() linux.FileMode {
	return fd.ftype
}

// IsDir indicates whether fd represents a directory.
func (fd *ControlFD) IsDir() bool {
	return fd.ftype == unix.S_IFDIR
}

// IsRegular indicates whether fd represents a regular file.
func (fd *ControlFD) IsRegular() bool {
	return fd.ftype == unix.S_IFREG
}

// IsSymlink indicates whether fd represents a symbolic link.
func (fd *ControlFD) IsSymlink() bool {
	return fd.ftype == unix.S_IFLNK
}

// IsSocket indicates whether fd represents a socket.
func (fd *ControlFD) IsSocket() bool {
	return fd.ftype == unix.S_IFSOCK
}

// NameLocked returns the backing file's last component name.
//
// Precondition: server's rename mutex must be at least read locked.
func (fd *ControlFD) NameLocked() string {
	return fd.name
}

// ParentLocked returns the parent control FD. Note that parent might be a
// control FD from another connection on this server. So its ID must not
// returned on this connection because FDIDs are local to their connection.
//
// Precondition: server's rename mutex must be at least read locked.
func (fd *ControlFD) ParentLocked() ControlFDImpl {
	if fd.parent == nil {
		return nil
	}
	return fd.parent.impl
}

// ID returns fd's ID.
func (fd *ControlFD) ID() FDID {
	return fd.id
}

// FilePath returns the absolute path of the file fd was opened on. This is
// expensive and must not be called on hot paths. FilePath acquires the rename
// mutex for reading so callers should not be holding it.
func (fd *ControlFD) FilePath() string {
	// Lock the rename mutex for reading to ensure that the filesystem tree is not
	// changed while we traverse it upwards.
	fd.conn.server.RenameMu.RLock()
	defer fd.conn.server.RenameMu.RUnlock()
	return fd.FilePathLocked()
}

// FilePathLocked is the same as FilePath with the additonal precondition.
//
// Precondition: server's rename mutex must be at least read locked.
func (fd *ControlFD) FilePathLocked() string {
	// Walk upwards and prepend name to res.
	var res fspath.Builder
	for fd != nil {
		res.PrependComponent(fd.name)
		fd = fd.parent
	}
	return res.String()
}

// ForEachOpenFD executes fn on each FD opened on fd.
func (fd *ControlFD) ForEachOpenFD(fn func(ofd OpenFDImpl)) {
	fd.openFDsMu.RLock()
	defer fd.openFDsMu.RUnlock()
	for ofd := fd.openFDs.Front(); ofd != nil; ofd = ofd.Next() {
		fn(ofd.impl)
	}
}

// OpenFD represents an open file descriptor on the protocol. It resonates
// closely with a Linux file descriptor. Its operations are limited to the
// file. Its operations are not allowed to modify or traverse the filesystem
// tree. See OpenFDImpl for the supported operations.
//
// Reference Model:
// * An OpenFD takes a reference on the control FD it was opened on.
type OpenFD struct {
	openFDRefs
	openFDEntry

	// All the following fields are immutable.

	// controlFD is the ControlFD on which this FD was opened. OpenFD holds a ref
	// on controlFD for its entire lifetime.
	controlFD *ControlFD

	// id is the unique FD identifier which identifies this FD on its connection.
	id FDID

	// Access mode for this FD.
	readable bool
	writable bool

	// impl is the open FD implementation which embeds this struct. It
	// contains all the implementation specific details.
	impl OpenFDImpl
}

var _ genericFD = (*OpenFD)(nil)

// ID returns fd's ID.
func (fd *OpenFD) ID() FDID {
	return fd.id
}

// ControlFD returns the control FD on which this FD was opened.
func (fd *OpenFD) ControlFD() ControlFDImpl {
	return fd.controlFD.impl
}

// DecRef implements refsvfs2.RefCounter.DecRef. Note that the context
// parameter should never be used. It exists solely to comply with the
// refsvfs2.RefCounter interface.
func (fd *OpenFD) DecRef(context.Context) {
	fd.openFDRefs.DecRef(func() {
		fd.controlFD.openFDsMu.Lock()
		fd.controlFD.openFDs.Remove(fd)
		fd.controlFD.openFDsMu.Unlock()
		fd.controlFD.DecRef(nil) // Drop the ref on the control FD.
		fd.impl.Close(fd.controlFD.conn)
	})
}

// Init must be called before first use of fd.
func (fd *OpenFD) Init(cfd *ControlFD, flags uint32, impl OpenFDImpl) {
	// Initialize fd with 1 ref which is transferred to c via c.insertFD().
	fd.openFDRefs.InitRefs()
	fd.controlFD = cfd
	fd.id = cfd.conn.insertFD(fd)
	accessMode := flags & unix.O_ACCMODE
	fd.readable = accessMode == unix.O_RDONLY || accessMode == unix.O_RDWR
	fd.writable = accessMode == unix.O_WRONLY || accessMode == unix.O_RDWR
	fd.impl = impl
	cfd.IncRef() // Holds a ref on cfd for its lifetime.
	cfd.openFDsMu.Lock()
	cfd.openFDs.PushBack(fd)
	cfd.openFDsMu.Unlock()
}

// ControlFDImpl contains implementation details for a ControlFD.
// Implementations of ControlFDImpl should contain their associated ControlFD
// by value as their first field.
//
// The operations that perform path traversal or any modification to the
// filesystem tree must synchronize those modifications with the server's
// rename mutex.
type ControlFDImpl interface {
	FD() *ControlFD
	Close(c *Connection)
}

// OpenFDImpl contains implementation details for a OpenFD. Implementations of
// OpenFDImpl should contain their associated OpenFD by value as their first
// field.
//
// Since these operations do not perform any path traversal or any modification
// to the filesystem tree, there is no need to synchronize with rename
// operations.
type OpenFDImpl interface {
	FD() *OpenFD
	Close(c *Connection)
}
