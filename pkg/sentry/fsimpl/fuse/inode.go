// Copyright 2022 The gVisor Authors.
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

package fuse

import (
	"fmt"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// +stateify savable
type fileHandle struct {
	new    bool
	handle uint64
	flags  uint32
}

// inode implements kernfs.Inode.
//
// +stateify savable
type inode struct {
	inodeRefs
	kernfs.InodeAlwaysValid
	kernfs.InodeNotAnonymous
	kernfs.InodeNotSymlink
	kernfs.InodeWatches
	kernfs.OrderedChildren
	kernfs.CachedMappable

	// the owning filesystem. fs is immutable.
	fs *filesystem

	// nodeID is a unique id which identifies the inode between userspace
	// and the sentry. Immutable.
	nodeID uint64

	// attrVersion is the version of the last attribute change.
	attrVersion atomicbitops.Uint64

	// attrTime is the time until the attributes are valid.
	attrTime uint64

	// link is result of following a symbolic link.
	link string

	// fh caches the file handle returned by the server from a FUSE_CREATE request
	// so we don't have to send a separate FUSE_OPEN request.
	fh fileHandle

	locks   vfs.FileLocks
	watches vfs.Watches

	// attrMu protects the attributes of this inode.
	attrMu sync.Mutex

	// +checklocks:attrMu
	ino atomicbitops.Uint64 // Stat data, not accessed for path walking.
	// +checklocks:attrMu
	uid atomicbitops.Uint32 // auth.KUID, but stored as raw uint32 for sync/atomic.
	// +checklocks:attrMu
	gid atomicbitops.Uint32 // auth.KGID, but...
	// +checklocks:attrMu
	mode atomicbitops.Uint32 // File type and mode.

	// Timestamps in nanoseconds from the unix epoch.
	// +checklocks:attrMu
	atime atomicbitops.Int64
	// +checklocks:attrMu
	mtime atomicbitops.Int64
	// +checklocks:attrMu
	ctime atomicbitops.Int64

	// +checklocks:attrMu
	size atomicbitops.Uint64

	// nlink counts the number of hard links to this inode. It's updated and
	// accessed used atomic operations but not protected by attrMu.
	nlink atomicbitops.Uint32

	// +checklocks:attrMu
	blockSize atomicbitops.Uint32 // 0 if unknown.
}

func blockerFromContext(ctx context.Context) context.Blocker {
	kernelTask := kernel.TaskFromContext(ctx)
	if kernelTask == nil {
		return ctx
	}
	return kernelTask
}

func pidFromContext(ctx context.Context) uint32 {
	kernelTask := kernel.TaskFromContext(ctx)
	if kernelTask == nil {
		return 0
	}
	return uint32(kernelTask.ThreadID())
}

func umaskFromContext(ctx context.Context) uint32 {
	kernelTask := kernel.TaskFromContext(ctx)
	umask := uint32(0)
	if kernelTask != nil {
		umask = uint32(kernelTask.FSContext().Umask())
	}
	return umask
}

func (i *inode) Mode() linux.FileMode {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return i.filemode()
}

func (i *inode) UID() auth.KUID {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return auth.KUID(i.uid.Load())
}

func (i *inode) GID() auth.KGID {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return auth.KGID(i.gid.Load())
}

// +checklocks:i.attrMu
func (i *inode) filemode() linux.FileMode {
	return linux.FileMode(i.mode.Load())
}

// touchCMTime updates the ctime and mtime attributes to be the current time.
//
// +checklocks:i.attrMu
func (i *inode) touchCMtime() {
	now := i.fs.clock.Now().Nanoseconds()
	i.mtime.Store(now)
	i.ctime.Store(now)
}

// touchAtime updates the atime attribut to be the current time.
//
// +checklocks:i.attrMu
func (i *inode) touchAtime() {
	i.atime.Store(i.fs.clock.Now().Nanoseconds())
}

// +checklocks:i.attrMu
func (i *inode) init(creds *auth.Credentials, devMajor, devMinor uint32, nodeid uint64, mode linux.FileMode, nlink uint32) {
	if mode.FileType() == 0 {
		panic(fmt.Sprintf("No file type specified in 'mode' for InodeAttrs.Init(): mode=0%o", mode))
	}

	i.nodeID = nodeid
	i.ino.Store(nodeid)
	i.mode.Store(uint32(mode))
	i.uid.Store(uint32(creds.EffectiveKUID))
	i.gid.Store(uint32(creds.EffectiveKGID))
	i.nlink.Store(nlink)
	i.blockSize.Store(hostarch.PageSize)

	now := i.fs.clock.Now().Nanoseconds()
	i.atime.Store(now)
	i.mtime.Store(now)
	i.ctime.Store(now)
}

// CheckPermissions implements kernfs.Inode.CheckPermissions.
func (i *inode) CheckPermissions(ctx context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error {
	// Since FUSE operations are ultimately backed by a userspace process (the
	// fuse daemon), allowing a process to call into fusefs grants the daemon
	// ptrace-like capabilities over the calling process. Because of this, by
	// default FUSE only allows the mount owner to interact with the
	// filesystem. This explicitly excludes setuid/setgid processes.
	//
	// This behaviour can be overriden with the 'allow_other' mount option.
	//
	// See fs/fuse/dir.c:fuse_allow_current_process() in Linux.
	if !i.fs.opts.allowOther {
		if creds.RealKUID != i.fs.opts.uid ||
			creds.EffectiveKUID != i.fs.opts.uid ||
			creds.SavedKUID != i.fs.opts.uid ||
			creds.RealKGID != i.fs.opts.gid ||
			creds.EffectiveKGID != i.fs.opts.gid ||
			creds.SavedKGID != i.fs.opts.gid {
			return linuxerr.EACCES
		}
	}

	// By default, fusefs delegates all permission checks to the server.
	// However, standard unix permission checks can be enabled with the
	// default_permissions mount option.
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	refreshed := false
	opts := vfs.StatOptions{Mask: linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID}
	if i.fs.opts.defaultPermissions || (ats.MayExec() && i.filemode().FileType() == linux.S_IFREG) {
		if uint64(i.fs.clock.Now().Nanoseconds()) > i.attrTime {
			refreshed = true
			if _, err := i.getAttr(ctx, i.fs.VFSFilesystem(), opts, 0, 0); err != nil {
				return err
			}
		}
	}

	if i.fs.opts.defaultPermissions || (ats.MayExec() && i.filemode().FileType() == linux.S_IFREG) {
		err := vfs.GenericCheckPermissions(creds, ats, linux.FileMode(i.mode.Load()), auth.KUID(i.uid.Load()), auth.KGID(i.gid.Load()))
		if linuxerr.Equals(linuxerr.EACCES, err) && !refreshed {
			if _, err := i.getAttr(ctx, i.fs.VFSFilesystem(), opts, 0, 0); err != nil {
				return err
			}
			return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(i.mode.Load()), auth.KUID(i.uid.Load()), auth.KGID(i.gid.Load()))
		}
		return err
	} else if ats.MayRead() || ats.MayWrite() || ats.MayExec() {
		in := linux.FUSEAccessIn{Mask: uint32(ats)}
		req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), i.nodeID, linux.FUSE_ACCESS, &in)
		res, err := i.fs.conn.Call(ctx, req)
		if err != nil {
			return err
		}
		return res.Error()
	}
	return nil
}

// Open implements kernfs.Inode.Open.
func (i *inode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	opts.Flags &= linux.O_ACCMODE | linux.O_CREAT | linux.O_EXCL | linux.O_TRUNC |
		linux.O_DIRECTORY | linux.O_NOFOLLOW | linux.O_NONBLOCK | linux.O_NOCTTY |
		linux.O_APPEND | linux.O_DIRECT
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	if opts.Flags&linux.O_LARGEFILE == 0 && i.size.Load() > linux.MAX_NON_LFS {
		return nil, linuxerr.EOVERFLOW
	}

	var (
		fd     *fileDescription
		fdImpl vfs.FileDescriptionImpl
		opcode linux.FUSEOpcode
	)
	switch i.filemode().FileType() {
	case linux.S_IFREG:
		regularFD := &regularFileFD{}
		fd = &(regularFD.fileDescription)
		fdImpl = regularFD
		opcode = linux.FUSE_OPEN
	case linux.S_IFDIR:
		if opts.Flags&linux.O_CREAT != 0 {
			return nil, linuxerr.EISDIR
		}
		if ats := vfs.AccessTypesForOpenFlags(&opts); ats.MayWrite() {
			return nil, linuxerr.EISDIR
		}
		if opts.Flags&linux.O_DIRECT != 0 {
			return nil, linuxerr.EINVAL
		}
		directoryFD := &directoryFD{}
		fd = &(directoryFD.fileDescription)
		fdImpl = directoryFD
		opcode = linux.FUSE_OPENDIR
	case linux.S_IFLNK:
		return nil, linuxerr.ELOOP
	}

	fd.LockFD.Init(&i.locks)
	// FOPEN_KEEP_CACHE is the default flag for noOpen.
	fd.OpenFlag = linux.FOPEN_KEEP_CACHE

	truncateRegFile := opts.Flags&linux.O_TRUNC != 0 && i.filemode().FileType() == linux.S_IFREG
	if truncateRegFile && (i.fh.new || !i.fs.conn.atomicOTrunc) {
		// If the regular file needs to be truncated, but the connection doesn't
		// support O_TRUNC or if we are optimizing away the Open RPC, then manually
		// truncate the file *before* Open. As per libfuse, "If [atomic O_TRUNC is]
		// disabled, and an application specifies O_TRUNC, fuse first calls
		// truncate() and then open() with O_TRUNC filtered out.".
		opts := vfs.SetStatOptions{Stat: linux.Statx{Size: 0, Mask: linux.STATX_SIZE}}
		if err := i.setAttr(ctx, i.fs.VFSFilesystem(), auth.CredentialsFromContext(ctx), opts, fhOptions{useFh: false}); err != nil {
			return nil, err
		}
	}

	if i.fh.new {
		fd.OpenFlag = i.fh.flags
		fd.Fh = i.fh.handle
		i.fh.new = false
		// Only send an open request when the FUSE server supports open or is
		// opening a directory.
	} else if !i.fs.conn.noOpen || i.filemode().IsDir() {
		in := linux.FUSEOpenIn{Flags: opts.Flags & ^uint32(linux.O_CREAT|linux.O_EXCL|linux.O_NOCTTY)}
		// Clear O_TRUNC if the server doesn't support it.
		if !i.fs.conn.atomicOTrunc {
			in.Flags &= ^uint32(linux.O_TRUNC)
		}

		req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), i.nodeID, opcode, &in)
		res, err := i.fs.conn.Call(ctx, req)
		if err != nil {
			return nil, err
		}
		if err := res.Error(); err != nil {
			if linuxerr.Equals(linuxerr.ENOSYS, err) && !i.filemode().IsDir() {
				i.fs.conn.noOpen = true
			} else {
				return nil, err
			}
		} else {
			out := linux.FUSEOpenOut{}
			if err := res.UnmarshalPayload(&out); err != nil {
				return nil, err
			}
			fd.OpenFlag = out.OpenFlag
			fd.Fh = out.Fh
			// Open was successful. Update inode's size if atomicOTrunc && O_TRUNC.
			if truncateRegFile && i.fs.conn.atomicOTrunc {
				i.fs.conn.mu.Lock()
				i.attrVersion.Store(i.fs.conn.attributeVersion.Add(1))
				i.fs.conn.mu.Unlock()
				i.size.Store(0)
				i.touchCMtime()
			}
		}
	}
	if i.filemode().IsDir() {
		fd.OpenFlag &= ^uint32(linux.FOPEN_DIRECT_IO)
	}

	// TODO(gvisor.dev/issue/3234): invalidate mmap after implemented it for FUSE Inode
	fd.DirectIO = fd.OpenFlag&linux.FOPEN_DIRECT_IO != 0
	fdOptions := &vfs.FileDescriptionOptions{}
	if fd.OpenFlag&linux.FOPEN_NONSEEKABLE != 0 {
		fdOptions.DenyPRead = true
		fdOptions.DenyPWrite = true
		fd.Nonseekable = true
	}

	if err := fd.vfsfd.Init(fdImpl, opts.Flags, rp.Mount(), d.VFSDentry(), fdOptions); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Lookup implements kernfs.Inode.Lookup.
func (i *inode) Lookup(ctx context.Context, name string) (kernfs.Inode, error) {
	in := linux.FUSELookupIn{Name: linux.CString(name)}
	return i.newEntry(ctx, name, 0, linux.FUSE_LOOKUP, &in)
}

// Keep implements kernfs.Inode.Keep.
func (i *inode) Keep() bool {
	// Return true so that kernfs keeps the new dentry pointing to this
	// inode in the dentry tree. This is needed because inodes created via
	// Lookup are not temporary. They might refer to existing files on server
	// that can be Unlink'd/Rmdir'd.
	return true
}

// IterDirents implements kernfs.Inode.IterDirents.
func (*inode) IterDirents(ctx context.Context, mnt *vfs.Mount, callback vfs.IterDirentsCallback, offset, relOffset int64) (int64, error) {
	return offset, nil
}

// NewFile implements kernfs.Inode.NewFile.
func (i *inode) NewFile(ctx context.Context, name string, opts vfs.OpenOptions) (kernfs.Inode, error) {
	opts.Flags &= linux.O_ACCMODE | linux.O_CREAT | linux.O_EXCL | linux.O_TRUNC |
		linux.O_DIRECTORY | linux.O_NOFOLLOW | linux.O_NONBLOCK | linux.O_NOCTTY
	in := linux.FUSECreateIn{
		CreateMeta: linux.FUSECreateMeta{
			Flags: opts.Flags,
			Mode:  uint32(opts.Mode) | linux.S_IFREG,
			Umask: umaskFromContext(ctx),
		},
		Name: linux.CString(name),
	}
	return i.newEntry(ctx, name, linux.S_IFREG, linux.FUSE_CREATE, &in)
}

// NewNode implements kernfs.Inode.NewNode.
func (i *inode) NewNode(ctx context.Context, name string, opts vfs.MknodOptions) (kernfs.Inode, error) {
	in := linux.FUSEMknodIn{
		MknodMeta: linux.FUSEMknodMeta{
			Mode:  uint32(opts.Mode),
			Rdev:  linux.MakeDeviceID(uint16(opts.DevMajor), opts.DevMinor),
			Umask: umaskFromContext(ctx),
		},
		Name: linux.CString(name),
	}
	return i.newEntry(ctx, name, opts.Mode.FileType(), linux.FUSE_MKNOD, &in)
}

// NewSymlink implements kernfs.Inode.NewSymlink.
func (i *inode) NewSymlink(ctx context.Context, name, target string) (kernfs.Inode, error) {
	in := linux.FUSESymlinkIn{
		Name:   linux.CString(name),
		Target: linux.CString(target),
	}
	return i.newEntry(ctx, name, linux.S_IFLNK, linux.FUSE_SYMLINK, &in)
}

// NewLink implements kernfs.Inode.NewLink.
func (i *inode) NewLink(ctx context.Context, name string, target kernfs.Inode) (kernfs.Inode, error) {
	targetInode := target.(*inode)
	in := linux.FUSELinkIn{
		OldNodeID: primitive.Uint64(targetInode.nodeID),
		Name:      linux.CString(name),
	}
	return i.newEntry(ctx, name, targetInode.Mode().FileType(), linux.FUSE_LINK, &in)
}

// Unlink implements kernfs.Inode.Unlink.
func (i *inode) Unlink(ctx context.Context, name string, child kernfs.Inode) error {
	in := linux.FUSEUnlinkIn{Name: linux.CString(name)}
	req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), i.nodeID, linux.FUSE_UNLINK, &in)
	res, err := i.fs.conn.Call(ctx, req)
	if err != nil {
		return err
	}
	// only return error, discard res.
	return res.Error()
}

// NewDir implements kernfs.Inode.NewDir.
func (i *inode) NewDir(ctx context.Context, name string, opts vfs.MkdirOptions) (kernfs.Inode, error) {
	in := linux.FUSEMkdirIn{
		MkdirMeta: linux.FUSEMkdirMeta{
			Mode:  uint32(opts.Mode),
			Umask: umaskFromContext(ctx),
		},
		Name: linux.CString(name),
	}
	return i.newEntry(ctx, name, linux.S_IFDIR, linux.FUSE_MKDIR, &in)
}

// RmDir implements kernfs.Inode.RmDir.
func (i *inode) RmDir(ctx context.Context, name string, child kernfs.Inode) error {
	in := linux.FUSERmDirIn{Name: linux.CString(name)}
	req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), i.nodeID, linux.FUSE_RMDIR, &in)
	res, err := i.fs.conn.Call(ctx, req)
	if err != nil {
		return err
	}
	return res.Error()
}

// Rename implements kernfs.Inode.Rename.
func (i *inode) Rename(ctx context.Context, oldname, newname string, child, dstDir kernfs.Inode) error {
	dstDirInode := dstDir.(*inode)
	in := linux.FUSERenameIn{
		Newdir:  primitive.Uint64(dstDirInode.nodeID),
		Oldname: linux.CString(oldname),
		Newname: linux.CString(newname),
	}
	req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), i.nodeID, linux.FUSE_RENAME, &in)
	res, err := i.fs.conn.Call(ctx, req)
	if err != nil {
		return err
	}
	return res.Error()
}

// newEntry calls FUSE server for entry creation and allocates corresponding
// entry according to response. Shared by FUSE_MKNOD, FUSE_MKDIR, FUSE_SYMLINK,
// FUSE_LINK and FUSE_LOOKUP.
func (i *inode) newEntry(ctx context.Context, name string, fileType linux.FileMode, opcode linux.FUSEOpcode, payload marshal.Marshallable) (kernfs.Inode, error) {
	req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), i.nodeID, opcode, payload)
	res, err := i.fs.conn.Call(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := res.Error(); err != nil {
		return nil, err
	}
	out := linux.FUSECreateOut{}
	if opcode == linux.FUSE_CREATE {
		if err := res.UnmarshalPayload(&out); err != nil {
			return nil, err
		}
	} else {
		if err := res.UnmarshalPayload(&out.FUSEEntryOut); err != nil {
			return nil, err
		}
	}
	if opcode != linux.FUSE_LOOKUP && ((out.Attr.Mode&linux.S_IFMT)^uint32(fileType) != 0 || out.NodeID == 0 || out.NodeID == linux.FUSE_ROOT_ID) {
		return nil, linuxerr.EIO
	}
	child := i.fs.newInode(ctx, out.NodeID, out.Attr)
	if opcode == linux.FUSE_CREATE {
		// File handler is returned by fuse server at a time of file create.
		// Save it temporary in a created child, so Open could return it when invoked
		// to be sure after fh is consumed reset 'isNewFh' flag of inode
		childI, ok := child.(*inode)
		if ok {
			childI.fh.new = true
			childI.fh.handle = out.FUSEOpenOut.Fh
			childI.fh.flags = out.FUSEOpenOut.OpenFlag
		}
	}
	return child, nil
}

// Getlink implements kernfs.Inode.Getlink.
func (i *inode) Getlink(ctx context.Context, mnt *vfs.Mount) (vfs.VirtualDentry, string, error) {
	path, err := i.Readlink(ctx, mnt)
	return vfs.VirtualDentry{}, path, err
}

// Readlink implements kernfs.Inode.Readlink.
func (i *inode) Readlink(ctx context.Context, mnt *vfs.Mount) (string, error) {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	if i.filemode().FileType()&linux.S_IFLNK == 0 {
		return "", linuxerr.EINVAL
	}
	if len(i.link) == 0 {
		req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), i.nodeID, linux.FUSE_READLINK, &linux.FUSEEmptyIn{})
		res, err := i.fs.conn.Call(ctx, req)
		if err != nil {
			return "", err
		}
		i.link = string(res.data[res.hdr.SizeBytes():])
		if !mnt.Options().ReadOnly {
			i.attrTime = 0
		}
	}
	return i.link, nil
}

// getFUSEAttr returns a linux.FUSEAttr of this inode stored in local cache.
//
// +checklocks:i.attrMu
func (i *inode) getFUSEAttr() linux.FUSEAttr {
	ns := time.Second.Nanoseconds()
	return linux.FUSEAttr{
		Ino:       i.nodeID,
		UID:       i.uid.Load(),
		GID:       i.gid.Load(),
		Size:      i.size.Load(),
		Mode:      uint32(i.filemode()),
		BlkSize:   i.blockSize.Load(),
		Atime:     uint64(i.atime.Load() / ns),
		Mtime:     uint64(i.mtime.Load() / ns),
		Ctime:     uint64(i.ctime.Load() / ns),
		AtimeNsec: uint32(i.atime.Load() % ns),
		MtimeNsec: uint32(i.mtime.Load() % ns),
		CtimeNsec: uint32(i.ctime.Load() % ns),
		Nlink:     i.nlink.Load(),
	}
}

// statFromFUSEAttr makes attributes from linux.FUSEAttr to linux.Statx. The
// opts.Sync attribute is ignored since the synchronization is handled by the
// FUSE server.
func statFromFUSEAttr(attr linux.FUSEAttr, mask, devMinor uint32) linux.Statx {
	var stat linux.Statx
	stat.Blksize = attr.BlkSize
	stat.DevMajor, stat.DevMinor = linux.UNNAMED_MAJOR, devMinor

	rdevMajor, rdevMinor := linux.DecodeDeviceID(attr.Rdev)
	stat.RdevMajor, stat.RdevMinor = uint32(rdevMajor), rdevMinor

	if mask&linux.STATX_MODE != 0 {
		stat.Mode = uint16(attr.Mode)
	}
	if mask&linux.STATX_NLINK != 0 {
		stat.Nlink = attr.Nlink
	}
	if mask&linux.STATX_UID != 0 {
		stat.UID = attr.UID
	}
	if mask&linux.STATX_GID != 0 {
		stat.GID = attr.GID
	}
	if mask&linux.STATX_ATIME != 0 {
		stat.Atime = linux.StatxTimestamp{
			Sec:  int64(attr.Atime),
			Nsec: attr.AtimeNsec,
		}
	}
	if mask&linux.STATX_MTIME != 0 {
		stat.Mtime = linux.StatxTimestamp{
			Sec:  int64(attr.Mtime),
			Nsec: attr.MtimeNsec,
		}
	}
	if mask&linux.STATX_CTIME != 0 {
		stat.Ctime = linux.StatxTimestamp{
			Sec:  int64(attr.Ctime),
			Nsec: attr.CtimeNsec,
		}
	}
	if mask&linux.STATX_INO != 0 {
		stat.Ino = attr.Ino
	}
	if mask&linux.STATX_SIZE != 0 {
		stat.Size = attr.Size
	}
	if mask&linux.STATX_BLOCKS != 0 {
		stat.Blocks = attr.Blocks
	}
	return stat
}

// getAttr gets the attribute of this inode by issuing a FUSE_GETATTR request
// or read from local cache. It updates the corresponding attributes if
// necessary.
//
// +checklocks:i.attrMu
func (i *inode) getAttr(ctx context.Context, fs *vfs.Filesystem, opts vfs.StatOptions, flags uint32, fh uint64) (linux.FUSEAttr, error) {
	// TODO(gvisor.dev/issue/3679): send the request only if
	//	- invalid local cache for fields specified in the opts.Mask
	//	- forced update
	//	- i.attributeTime expired
	// If local cache is still valid, return local cache.
	// Currently we always send a request,
	// and we always set the metadata with the new result,
	// unless attributeVersion has changed.
	creds := auth.CredentialsFromContext(ctx)

	in := linux.FUSEGetAttrIn{
		GetAttrFlags: flags,
		Fh:           fh,
	}
	req := i.fs.conn.NewRequest(creds, pidFromContext(ctx), i.nodeID, linux.FUSE_GETATTR, &in)
	res, err := i.fs.conn.Call(ctx, req)
	if err != nil {
		return linux.FUSEAttr{}, err
	}
	if err := res.Error(); err != nil {
		return linux.FUSEAttr{}, err
	}
	var out linux.FUSEAttrOut
	if err := res.UnmarshalPayload(&out); err != nil {
		return linux.FUSEAttr{}, err
	}

	// Local version is newer, return the local one.
	i.fs.conn.mu.Lock()
	attributeVersion := i.fs.conn.attributeVersion.Load()
	if attributeVersion != 0 && i.attrVersion.Load() > attributeVersion {
		i.fs.conn.mu.Unlock()
		return i.getFUSEAttr(), nil
	}
	i.fs.conn.mu.Unlock()
	i.updateAttrs(out.Attr, out.AttrValid)
	return out.Attr, nil
}

// reviseAttr attempts to update the attributes for internal purposes
// by calling getAttr with a pre-specified mask.
// Used by read, write, lseek.
//
// +checklocks:i.attrMu
func (i *inode) reviseAttr(ctx context.Context, flags uint32, fh uint64) error {
	// Never need atime for internal purposes.
	_, err := i.getAttr(ctx, i.fs.VFSFilesystem(), vfs.StatOptions{
		Mask: linux.STATX_BASIC_STATS &^ linux.STATX_ATIME,
	}, flags, fh)
	return err
}

// Stat implements kernfs.Inode.Stat.
func (i *inode) Stat(ctx context.Context, fs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	attr, err := i.getAttr(ctx, fs, opts, 0, 0)
	if err != nil {
		return linux.Statx{}, err
	}

	return statFromFUSEAttr(attr, opts.Mask, i.fs.devMinor), nil
}

// DecRef implements kernfs.Inode.DecRef.
func (i *inode) DecRef(ctx context.Context) {
	i.inodeRefs.DecRef(func() { i.Destroy(ctx) })
}

// StatFS implements kernfs.Inode.StatFS.
func (i *inode) StatFS(ctx context.Context, fs *vfs.Filesystem) (linux.Statfs, error) {
	req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), i.nodeID,
		linux.FUSE_STATFS, &linux.FUSEEmptyIn{},
	)
	res, err := i.fs.conn.Call(ctx, req)
	if err != nil {
		return linux.Statfs{}, err
	}
	if err := res.Error(); err != nil {
		return linux.Statfs{}, err
	}

	var out linux.FUSEStatfsOut
	if err := res.UnmarshalPayload(&out); err != nil {
		return linux.Statfs{}, err
	}

	return linux.Statfs{
		Type:            linux.FUSE_SUPER_MAGIC,
		Blocks:          uint64(out.Blocks),
		BlocksFree:      out.BlocksFree,
		BlocksAvailable: out.BlocksAvailable,
		Files:           out.Files,
		FilesFree:       out.FilesFree,
		BlockSize:       int64(out.BlockSize),
		NameLength:      uint64(out.NameLength),
		FragmentSize:    int64(out.FragmentSize),
	}, nil
}

// fattrMaskFromStats converts vfs.SetStatOptions.Stat.Mask to linux stats mask
// aligned with the attribute mask defined in include/linux/fs.h.
func fattrMaskFromStats(mask uint32) uint32 {
	var fuseAttrMask uint32
	maskMap := map[uint32]uint32{
		linux.STATX_MODE:  linux.FATTR_MODE,
		linux.STATX_UID:   linux.FATTR_UID,
		linux.STATX_GID:   linux.FATTR_GID,
		linux.STATX_SIZE:  linux.FATTR_SIZE,
		linux.STATX_ATIME: linux.FATTR_ATIME,
		linux.STATX_MTIME: linux.FATTR_MTIME,
		linux.STATX_CTIME: linux.FATTR_CTIME,
	}
	for statxMask, fattrMask := range maskMap {
		if mask&statxMask != 0 {
			fuseAttrMask |= fattrMask
		}
	}
	return fuseAttrMask
}

// SetStat implements kernfs.Inode.SetStat.
func (i *inode) SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	if err := vfs.CheckSetStat(ctx, creds, &opts, i.filemode(), auth.KUID(i.uid.Load()), auth.KGID(i.gid.Load())); err != nil {
		return err
	}
	if opts.Stat.Mask == 0 {
		return nil
	}
	return i.setAttr(ctx, fs, creds, opts, fhOptions{useFh: false})
}

type fhOptions struct {
	useFh bool
	fh    uint64
}

// +checklocks:i.attrMu
func (i *inode) setAttr(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions, fhOpts fhOptions) error {
	// We should retain the original file type when assigning a new mode.
	fattrMask := fattrMaskFromStats(opts.Stat.Mask)
	if fhOpts.useFh {
		fattrMask |= linux.FATTR_FH
	}
	if opts.Stat.Mask&linux.STATX_ATIME != 0 && opts.Stat.Atime.Nsec == linux.UTIME_NOW {
		fattrMask |= linux.FATTR_ATIME_NOW
	}
	if opts.Stat.Mask&linux.STATX_MTIME != 0 && opts.Stat.Mtime.Nsec == linux.UTIME_NOW {
		fattrMask |= linux.FATTR_ATIME_NOW
	}
	in := linux.FUSESetAttrIn{
		Valid:     fattrMask,
		Fh:        fhOpts.fh,
		Size:      opts.Stat.Size,
		Atime:     uint64(opts.Stat.Atime.Sec),
		Mtime:     uint64(opts.Stat.Mtime.Sec),
		Ctime:     uint64(opts.Stat.Ctime.Sec),
		AtimeNsec: opts.Stat.Atime.Nsec,
		MtimeNsec: opts.Stat.Mtime.Nsec,
		CtimeNsec: opts.Stat.Ctime.Nsec,
		Mode:      uint32(uint16(i.filemode().FileType()) | opts.Stat.Mode),
		UID:       opts.Stat.UID,
		GID:       opts.Stat.GID,
	}
	req := i.fs.conn.NewRequest(creds, pidFromContext(ctx), i.nodeID, linux.FUSE_SETATTR, &in)
	res, err := i.fs.conn.Call(ctx, req)
	if err != nil {
		return err
	}
	if err := res.Error(); err != nil {
		return err
	}
	out := linux.FUSEAttrOut{}
	if err := res.UnmarshalPayload(&out); err != nil {
		return err
	}
	i.updateAttrs(out.Attr, out.AttrValid)
	return nil
}

// +checklocks:i.attrMu
func (i *inode) updateAttrs(attr linux.FUSEAttr, attrTimeout uint64) {
	i.fs.conn.mu.Lock()
	i.attrVersion.Store(i.fs.conn.attributeVersion.Add(1))
	i.fs.conn.mu.Unlock()
	i.attrTime = attrTimeout

	i.ino.Store(attr.Ino)

	i.mode.Store((attr.Mode & 07777) | (i.mode.Load() & linux.S_IFMT))
	i.uid.Store(attr.UID)
	i.gid.Store(attr.GID)

	i.atime.Store(attr.ATimeNsec())
	i.mtime.Store(attr.MTimeNsec())
	i.ctime.Store(attr.CTimeNsec())

	i.size.Store(attr.Size)
	i.nlink.Store(attr.Nlink)

	if !i.fs.opts.defaultPermissions {
		i.mode.Store(i.mode.Load() & ^uint32(linux.S_ISVTX))
	}
}
