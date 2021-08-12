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

// Package tty provide pseudoterminals via a devpts filesystem.
package tty

import (
	"fmt"
	"math"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// dirInodeOperations is the root of a devpts mount.
//
// This indirectly manages all terminals within the mount.
//
// New Terminals are created by masterInodeOperations.GetFile, which registers
// the replica Inode in the this directory for discovery via Lookup/Readdir. The
// replica inode is unregistered when the master file is Released, as the replica
// is no longer discoverable at that point.
//
// References on the underlying Terminal are held by masterFileOperations and
// replicaInodeOperations.
//
// masterInodeOperations and replicaInodeOperations hold a pointer to
// dirInodeOperations, which is reference counted by the refcount their
// corresponding Dirents hold on their parent (this directory).
//
// dirInodeOperations implements fs.InodeOperations.
//
// +stateify savable
type dirInodeOperations struct {
	fsutil.InodeGenericChecker       `state:"nosave"`
	fsutil.InodeIsDirAllocate        `state:"nosave"`
	fsutil.InodeIsDirTruncate        `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNoopWriteOut         `state:"nosave"`
	fsutil.InodeNotMappable          `state:"nosave"`
	fsutil.InodeNotRenameable        `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`
	fsutil.InodeVirtual              `state:"nosave"`

	fsutil.InodeSimpleAttributes

	// msrc is the super block this directory is on.
	//
	// TODO(chrisko): Plumb this through instead of storing it here.
	msrc *fs.MountSource

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// master is the master PTY inode.
	master *fs.Inode

	// replicas contains the replica inodes reachable from the directory.
	//
	// A new replica is added by allocateTerminal and is removed by
	// masterFileOperations.Release.
	//
	// A reference is held on every replica in the map.
	replicas map[uint32]*fs.Inode

	// dentryMap is a SortedDentryMap used to implement Readdir containing
	// the master and all entries in replicas.
	dentryMap *fs.SortedDentryMap

	// next is the next pty index to use.
	//
	// TODO(b/29356795): reuse indices when ptys are closed.
	next uint32
}

var _ fs.InodeOperations = (*dirInodeOperations)(nil)

// newDir creates a new dir with a ptmx file and no terminals.
func newDir(ctx context.Context, m *fs.MountSource) *fs.Inode {
	d := &dirInodeOperations{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, fs.RootOwner, fs.FilePermsFromMode(0555), linux.DEVPTS_SUPER_MAGIC),
		msrc:                  m,
		replicas:              make(map[uint32]*fs.Inode),
		dentryMap:             fs.NewSortedDentryMap(nil),
	}
	// Linux devpts uses a default mode of 0000 for ptmx which can be
	// changed with the ptmxmode mount option. However, that default is not
	// useful here (since we'd *always* need the mount option, so it is
	// accessible by default).
	d.master = newMasterInode(ctx, d, fs.RootOwner, fs.FilePermsFromMode(0666))
	d.dentryMap.Add("ptmx", fs.DentAttr{
		Type:    d.master.StableAttr.Type,
		InodeID: d.master.StableAttr.InodeID,
	})

	return fs.NewInode(ctx, d, m, fs.StableAttr{
		DeviceID: ptsDevice.DeviceID(),
		// N.B. Linux always uses inode id 1 for the directory. See
		// fs/devpts/inode.c:devpts_fill_super.
		//
		// TODO(b/75267214): Since ptsDevice must be shared between
		// different mounts, we must not assign fixed numbers.
		InodeID:   ptsDevice.NextIno(),
		BlockSize: hostarch.PageSize,
		Type:      fs.Directory,
	})
}

// Release implements fs.InodeOperations.Release.
func (d *dirInodeOperations) Release(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.master.DecRef(ctx)
	if len(d.replicas) != 0 {
		panic(fmt.Sprintf("devpts directory still contains active terminals: %+v", d))
	}
}

// Lookup implements fs.InodeOperations.Lookup.
func (d *dirInodeOperations) Lookup(ctx context.Context, dir *fs.Inode, name string) (*fs.Dirent, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Master?
	if name == "ptmx" {
		d.master.IncRef()
		return fs.NewDirent(ctx, d.master, name), nil
	}

	// Replica number?
	n, err := strconv.ParseUint(name, 10, 32)
	if err != nil {
		// Not found.
		return nil, linuxerr.ENOENT
	}

	s, ok := d.replicas[uint32(n)]
	if !ok {
		return nil, linuxerr.ENOENT
	}

	s.IncRef()
	return fs.NewDirent(ctx, s, name), nil
}

// Create implements fs.InodeOperations.Create.
//
// Creation is never allowed.
func (d *dirInodeOperations) Create(ctx context.Context, dir *fs.Inode, name string, flags fs.FileFlags, perm fs.FilePermissions) (*fs.File, error) {
	return nil, linuxerr.EACCES
}

// CreateDirectory implements fs.InodeOperations.CreateDirectory.
//
// Creation is never allowed.
func (d *dirInodeOperations) CreateDirectory(ctx context.Context, dir *fs.Inode, name string, perm fs.FilePermissions) error {
	return linuxerr.EACCES
}

// CreateLink implements fs.InodeOperations.CreateLink.
//
// Creation is never allowed.
func (d *dirInodeOperations) CreateLink(ctx context.Context, dir *fs.Inode, oldname, newname string) error {
	return linuxerr.EACCES
}

// CreateHardLink implements fs.InodeOperations.CreateHardLink.
//
// Creation is never allowed.
func (d *dirInodeOperations) CreateHardLink(ctx context.Context, dir *fs.Inode, target *fs.Inode, name string) error {
	return linuxerr.EACCES
}

// CreateFifo implements fs.InodeOperations.CreateFifo.
//
// Creation is never allowed.
func (d *dirInodeOperations) CreateFifo(ctx context.Context, dir *fs.Inode, name string, perm fs.FilePermissions) error {
	return linuxerr.EACCES
}

// Remove implements fs.InodeOperations.Remove.
//
// Removal is never allowed.
func (d *dirInodeOperations) Remove(ctx context.Context, dir *fs.Inode, name string) error {
	return linuxerr.EPERM
}

// RemoveDirectory implements fs.InodeOperations.RemoveDirectory.
//
// Removal is never allowed.
func (d *dirInodeOperations) RemoveDirectory(ctx context.Context, dir *fs.Inode, name string) error {
	return linuxerr.EPERM
}

// Bind implements fs.InodeOperations.Bind.
func (d *dirInodeOperations) Bind(ctx context.Context, dir *fs.Inode, name string, data transport.BoundEndpoint, perm fs.FilePermissions) (*fs.Dirent, error) {
	return nil, linuxerr.EPERM
}

// GetFile implements fs.InodeOperations.GetFile.
func (d *dirInodeOperations) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &dirFileOperations{di: d}), nil
}

// allocateTerminal creates a new Terminal and installs a pts node for it.
//
// The caller must call DecRef when done with the returned Terminal.
func (d *dirInodeOperations) allocateTerminal(ctx context.Context) (*Terminal, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	n := d.next
	if n == math.MaxUint32 {
		return nil, linuxerr.ENOMEM
	}

	if _, ok := d.replicas[n]; ok {
		panic(fmt.Sprintf("pty index collision; index %d already exists", n))
	}

	t := newTerminal(ctx, d, n)
	d.next++

	// The reference returned by newTerminal is returned to the caller.
	// Take another for the replica inode.
	t.IncRef()

	// Create a pts node. The owner is based on the context that opens
	// ptmx.
	creds := auth.CredentialsFromContext(ctx)
	uid, gid := creds.EffectiveKUID, creds.EffectiveKGID
	replica := newReplicaInode(ctx, d, t, fs.FileOwner{uid, gid}, fs.FilePermsFromMode(0666))

	d.replicas[n] = replica
	d.dentryMap.Add(strconv.FormatUint(uint64(n), 10), fs.DentAttr{
		Type:    replica.StableAttr.Type,
		InodeID: replica.StableAttr.InodeID,
	})

	return t, nil
}

// masterClose is called when the master end of t is closed.
func (d *dirInodeOperations) masterClose(ctx context.Context, t *Terminal) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// The replica end disappears from the directory when the master end is
	// closed, even if the replica end is open elsewhere.
	//
	// N.B. since we're using a backdoor method to remove a directory entry
	// we won't properly fire inotify events like Linux would.
	s, ok := d.replicas[t.n]
	if !ok {
		panic(fmt.Sprintf("Terminal %+v doesn't exist in %+v?", t, d))
	}

	s.DecRef(ctx)
	delete(d.replicas, t.n)
	d.dentryMap.Remove(strconv.FormatUint(uint64(t.n), 10))
}

// dirFileOperations are the fs.FileOperations for the directory.
//
// This is nearly identical to fsutil.DirFileOperations, except that it takes
// df.di.mu in IterateDir.
//
// +stateify savable
type dirFileOperations struct {
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`

	// di is the inode operations.
	di *dirInodeOperations

	// dirCursor contains the name of the last directory entry that was
	// serialized.
	dirCursor string
}

var _ fs.FileOperations = (*dirFileOperations)(nil)

// IterateDir implements DirIterator.IterateDir.
func (df *dirFileOperations) IterateDir(ctx context.Context, d *fs.Dirent, dirCtx *fs.DirCtx, offset int) (int, error) {
	df.di.mu.Lock()
	defer df.di.mu.Unlock()

	n, err := fs.GenericReaddir(dirCtx, df.di.dentryMap)
	return offset + n, err
}

// Readdir implements FileOperations.Readdir.
func (df *dirFileOperations) Readdir(ctx context.Context, file *fs.File, serializer fs.DentrySerializer) (int64, error) {
	root := fs.RootFromContext(ctx)
	if root != nil {
		defer root.DecRef(ctx)
	}
	dirCtx := &fs.DirCtx{
		Serializer: serializer,
		DirCursor:  &df.dirCursor,
	}
	return fs.DirentReaddir(ctx, file.Dirent, df, root, dirCtx, file.Offset())
}

// Read implements FileOperations.Read
func (df *dirFileOperations) Read(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, linuxerr.EISDIR
}

// Write implements FileOperations.Write.
func (df *dirFileOperations) Write(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, linuxerr.EISDIR
}
