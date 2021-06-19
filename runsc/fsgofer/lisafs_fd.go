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

package fsgofer

import (
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/lisafs"
)

// fdLisa represents a host file descriptor and implements lisafs.FD.
//
// Reference Model:
// The connection holds a ref on this FD until the client is done using this
// FD. All requests that use this FD also hold a ref on it for their entire
// lifetime so that the FD is not destroyed preemptively. After the FD is
// destroyed (when all refs are dropped), the FD number is set to -1 to make
// future FD usages fail.
//
// Each child control FD holds a ref on its parent control FD for its entire
// lifetime. This ref is dropped when the child control FD is destroyed.
//
// Control FDs:
// Control FDs are file descriptors that are used by the client to perform
// path based filesystem operations. These represent a file at a path and
// are only opened when an RPC responds an Inode.
//
// These are initially opened as read only (or with O_PATH if it represents a
// symlink or socket). The reason it is not opened as read-write is for better
// performance with 'overlay2' storage driver. overlay2 eagerly copies the
// entire file up when it's opened in write mode, and would perform badly when
// multiple files are only being opened for read (esp. startup).
//
// Avoid path based syscalls:
// File operations must use "at" functions whenever possible:
//   * Local operations must use AT_EMPTY_PATH:
//  	   fchownat(fd, "", AT_EMPTY_PATH, ...), instead of chown(fullpath, ...)
//   * Creation operations must use (fd + name):
//       mkdirat(fd, name, ...), instead of mkdir(fullpath, ...)
//
// Apart from being faster, it also adds another layer of defense against
// symlink attacks (note that O_NOFOLLOW applies only to the last element in
// the path).
//
// The few exceptions where path based operations can be done are: opening the
// root directory on Mount and Connect() for the socket address.
type fdLisa struct {
	fdLisaRefs

	// node represents the backing file's position in the filesystem tree. It is
	// protected by the server's rename mutex.
	node *node

	// All fields below are immutable.

	// id is used to identify this FD. id is guaranteed to be unique in a
	// connection's namespace.
	id lisafs.FDID

	// isControlFD indicates whether this is a control FD.
	isControlFD bool

	// ftype is equivalent to unix.Stat_t.Mode & unix.S_IFMT.
	ftype uint32

	// no is the file descriptor number which can be used to make syscalls.
	no int

	// readable denotes whether this FD was opened with read access.
	readable bool

	// writable denotes whether this FD was opened with write access.
	writable bool
}

var _ lisafs.FD = (*fdLisa)(nil)

// node represents a node on the filesystem tree. Multiple FDs (control and
// non-control) on the same node share the same node struct.
type node struct {
	// name is the file path's last component name. If this FD represents the
	// root directory, then name is "".
	name string

	// parent is parent directory's FD. Protected by server's rename mutex.
	// parent is always a control FD. If the node represents the root directory,
	// then parent is nil.
	parent *fdLisa
}

// initInode initializes the passed inode based on fd.
func (fd *fdLisa) initInode(inode *lisafs.Inode) error {
	inode.ControlFD = fd.id
	return fd.fstatTo(&inode.Stat)
}

func (fd *fdLisa) initInodeWithStat(inode *lisafs.Inode, stat *unix.Stat_t) {
	inode.ControlFD = fd.id
	inode.Stat.FromUnix(stat)
}

// initRefs intitializes the FD's reference counter and takes a ref on the
// parent. It also makes the FD visible for use on the connection. initRefs
// must be called before use.
func (fd *fdLisa) initRefs(c *lisafs.Connection) {
	// Initialize fd with 1 ref which is transferred to c via c.InsertFD().
	fd.fdLisaRefs.InitRefs()
	fd.id = c.InsertFD(fd)
	if fd.isControlFD && fd.node.parent != nil {
		// The control FD of the child takes a ref on the parent.
		fd.node.parent.IncRef()
	}
}

// DecRef implements refsvfs2.RefCounter.DecRef. Note that the context
// parameter should never be used as fsgofer has no context. It exists solely
// to comply with refsvfs2.RefCounter interface.
func (fd *fdLisa) DecRef(context.Context) {
	fd.fdLisaRefs.DecRef(func() {
		unix.Close(fd.no)
		fd.no = -1
		// No need to lock the rename mutex as no refs on fd are left so it could
		// not possibly be renamed concurrently (which would change fd.node).
		if fd.isControlFD && fd.node.parent != nil {
			fd.node.parent.DecRef(nil) // Drop the ref on the parent.
		}
	})
}

// hostPath returns the host path of the file fd was opened on. This is
// expensive and must not be called on hot paths. hostPath acquires the rename
// mutex for reading so callers should not be holding it.
func (fd *fdLisa) hostPath(c *lisafs.Connection) (path string) {
	// Lock the rename mutex for reading to ensure that the filesystem tree is not
	// changed while we traverse it upwards.
	c.WithRenameRLock(func() error {
		path = fd.hostPathLocked(c)
		return nil
	})
	return
}

// hostPathLocked is the same as hostPath with an extra precondition.
//
// Precondition: Server's rename mutex must be locked at least for reading.
func (fd *fdLisa) hostPathLocked(c *lisafs.Connection) string {
	// Walk upwards and prepend name to res.
	res := ""
	for fd.node.parent != nil {
		// fd represents a non-root file. fd.node.name is valid.
		res = string(os.PathSeparator) + fd.node.name + res // path.Join() is expensive.
		fd = fd.node.parent
	}
	return c.AttachPath() + res
}

func (fd *fdLisa) fstatTo(stat *lisafs.Statx) error {
	var unixStat unix.Stat_t
	if err := unix.Fstat(fd.no, &unixStat); err != nil {
		return err
	}

	stat.FromUnix(&unixStat)
	return nil
}
