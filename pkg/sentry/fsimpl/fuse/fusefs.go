// Copyright 2020 The gVisor Authors.
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

// Package fuse implements fusefs.
package fuse

import (
	"math"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
)

// Name is the default filesystem name.
const Name = "fuse"

// FilesystemType implements vfs.FilesystemType.
type FilesystemType struct{}

type filesystemOptions struct {
	// userID specifies the numeric uid of the mount owner.
	// This option should not be specified by the filesystem owner.
	// It is set by libfuse (or, if libfuse is not used, must be set
	// by the filesystem itself). For more information, see man page
	// for fuse(8)
	userID uint32

	// groupID specifies the numeric gid of the mount owner.
	// This option should not be specified by the filesystem owner.
	// It is set by libfuse (or, if libfuse is not used, must be set
	// by the filesystem itself). For more information, see man page
	// for fuse(8)
	groupID uint32

	// rootMode specifies the the file mode of the filesystem's root.
	rootMode linux.FileMode

	// maxActiveRequests specifies the maximum number of active requests that can
	// exist at any time. Any further requests will block when trying to
	// Call the server.
	maxActiveRequests uint64

	// maxRead is the max number of bytes to read.
	// specified as "max_read" in fs parameters.
	maxRead uint32
}

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	kernfs.Filesystem
	devMinor uint32

	// conn is used for communication between the FUSE server
	// daemon and the sentry fusefs.
	conn *connection

	// opts is the options the fusefs is initialized with.
	opts *filesystemOptions
}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fsType FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}

	var fsopts filesystemOptions
	mopts := vfs.GenericParseMountOptions(opts.Data)
	deviceDescriptorStr, ok := mopts["fd"]
	if !ok {
		log.Warningf("%s.GetFilesystem: communication file descriptor N (obtained by opening /dev/fuse) must be specified as 'fd=N'", fsType.Name())
		return nil, nil, syserror.EINVAL
	}
	delete(mopts, "fd")

	deviceDescriptor, err := strconv.ParseInt(deviceDescriptorStr, 10 /* base */, 32 /* bitSize */)
	if err != nil {
		return nil, nil, err
	}

	kernelTask := kernel.TaskFromContext(ctx)
	if kernelTask == nil {
		log.Warningf("%s.GetFilesystem: couldn't get kernel task from context", fsType.Name())
		return nil, nil, syserror.EINVAL
	}
	fuseFd := kernelTask.GetFileVFS2(int32(deviceDescriptor))

	// Parse and set all the other supported FUSE mount options.
	// TODO(gVisor.dev/issue/3229): Expand the supported mount options.
	if userIDStr, ok := mopts["user_id"]; ok {
		delete(mopts, "user_id")
		userID, err := strconv.ParseUint(userIDStr, 10, 32)
		if err != nil {
			log.Warningf("%s.GetFilesystem: invalid user_id: user_id=%s", fsType.Name(), userIDStr)
			return nil, nil, syserror.EINVAL
		}
		fsopts.userID = uint32(userID)
	}

	if groupIDStr, ok := mopts["group_id"]; ok {
		delete(mopts, "group_id")
		groupID, err := strconv.ParseUint(groupIDStr, 10, 32)
		if err != nil {
			log.Warningf("%s.GetFilesystem: invalid group_id: group_id=%s", fsType.Name(), groupIDStr)
			return nil, nil, syserror.EINVAL
		}
		fsopts.groupID = uint32(groupID)
	}

	rootMode := linux.FileMode(0777)
	modeStr, ok := mopts["rootmode"]
	if ok {
		delete(mopts, "rootmode")
		mode, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil {
			log.Warningf("%s.GetFilesystem: invalid mode: %q", fsType.Name(), modeStr)
			return nil, nil, syserror.EINVAL
		}
		rootMode = linux.FileMode(mode)
	}
	fsopts.rootMode = rootMode

	// Set the maxInFlightRequests option.
	fsopts.maxActiveRequests = maxActiveRequestsDefault

	if maxReadStr, ok := mopts["max_read"]; ok {
		delete(mopts, "max_read")
		maxRead, err := strconv.ParseUint(maxReadStr, 10, 32)
		if err != nil {
			log.Warningf("%s.GetFilesystem: invalid max_read: max_read=%s", fsType.Name(), maxReadStr)
			return nil, nil, syserror.EINVAL
		}
		fsopts.maxRead = uint32(maxRead)
	} else {
		fsopts.maxRead = math.MaxUint32
	}

	// Check for unparsed options.
	if len(mopts) != 0 {
		log.Warningf("%s.GetFilesystem: unknown options: %v", fsType.Name(), mopts)
		return nil, nil, syserror.EINVAL
	}

	// Create a new FUSE filesystem.
	fs, err := NewFUSEFilesystem(ctx, devMinor, &fsopts, fuseFd)
	if err != nil {
		log.Warningf("%s.NewFUSEFilesystem: failed with error: %v", fsType.Name(), err)
		return nil, nil, err
	}

	fs.VFSFilesystem().Init(vfsObj, &fsType, fs)

	// Send a FUSE_INIT request to the FUSE daemon server before returning.
	// This call is not blocking.
	if err := fs.conn.InitSend(creds, uint32(kernelTask.ThreadID())); err != nil {
		log.Warningf("%s.InitSend: failed with error: %v", fsType.Name(), err)
		return nil, nil, err
	}

	// root is the fusefs root directory.
	root := fs.newRootInode(creds, fsopts.rootMode)

	return fs.VFSFilesystem(), root.VFSDentry(), nil
}

// NewFUSEFilesystem creates a new FUSE filesystem.
func NewFUSEFilesystem(ctx context.Context, devMinor uint32, opts *filesystemOptions, device *vfs.FileDescription) (*filesystem, error) {
	fs := &filesystem{
		devMinor: devMinor,
		opts:     opts,
	}

	conn, err := newFUSEConnection(ctx, device, opts)
	if err != nil {
		log.Warningf("fuse.NewFUSEFilesystem: NewFUSEConnection failed with error: %v", err)
		return nil, syserror.EINVAL
	}

	fs.conn = conn
	fuseFD := device.Impl().(*DeviceFD)
	fuseFD.fs = fs

	return fs, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release(ctx)
}

// inode implements kernfs.Inode.
type inode struct {
	inodeRefs
	kernfs.InodeAttrs
	kernfs.InodeNoDynamicLookup
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren
	kernfs.OrderedChildren

	NodeID uint64
	dentry kernfs.Dentry
	locks  vfs.FileLocks

	// the owning filesystem. fs is immutable.
	fs *filesystem

	// size of the file.
	size uint64

	// attributeVersion is the version of inode's attributes.
	attributeVersion uint64

	// attributeTime is the remaining vaild time of attributes.
	attributeTime uint64

	// version of the inode.
	version uint64

	// link is result of following a symbolic link.
	link string
}

func (fs *filesystem) newRootInode(creds *auth.Credentials, mode linux.FileMode) *kernfs.Dentry {
	i := &inode{fs: fs}
	i.InodeAttrs.Init(creds, linux.UNNAMED_MAJOR, fs.devMinor, 1, linux.ModeDirectory|0755)
	i.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	i.dentry.Init(i)
	i.NodeID = 1

	return &i.dentry
}

func (fs *filesystem) newInode(nodeID uint64, attr linux.FUSEAttr) *kernfs.Dentry {
	i := &inode{fs: fs, NodeID: nodeID}
	creds := auth.Credentials{EffectiveKGID: auth.KGID(attr.UID), EffectiveKUID: auth.KUID(attr.UID)}
	i.InodeAttrs.Init(&creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.FileMode(attr.Mode))
	i.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	i.EnableLeakCheck()
	i.dentry.Init(i)

	return &i.dentry
}

// Open implements kernfs.Inode.Open.
func (i *inode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	isDir := i.InodeAttrs.Mode().IsDir()
	// return error if specified to open directory but inode is not a directory.
	if !isDir && opts.Mode.IsDir() {
		return nil, syserror.ENOTDIR
	}
	if opts.Flags&linux.O_LARGEFILE == 0 && i.size > linux.MAX_NON_LFS {
		return nil, syserror.EOVERFLOW
	}

	var fd *fileDescription
	var fdImpl vfs.FileDescriptionImpl
	if isDir {
		directoryFD := &directoryFD{}
		fd = &(directoryFD.fileDescription)
		fdImpl = directoryFD
	} else {
		regularFd := &regularFileFD{}
		fd = &(regularFd.fileDescription)
		fdImpl = regularFd
	}
	// FOPEN_KEEP_CACHE is the defualt flag for noOpen.
	fd.OpenFlag = linux.FOPEN_KEEP_CACHE

	// Only send open request when FUSE server support open or is opening a directory.
	if !i.fs.conn.noOpen || isDir {
		kernelTask := kernel.TaskFromContext(ctx)
		if kernelTask == nil {
			log.Warningf("fusefs.Inode.Open: couldn't get kernel task from context")
			return nil, syserror.EINVAL
		}

		// Build the request.
		var opcode linux.FUSEOpcode
		if isDir {
			opcode = linux.FUSE_OPENDIR
		} else {
			opcode = linux.FUSE_OPEN
		}

		in := linux.FUSEOpenIn{Flags: opts.Flags & ^uint32(linux.O_CREAT|linux.O_EXCL|linux.O_NOCTTY)}
		if !i.fs.conn.atomicOTrunc {
			in.Flags &= ^uint32(linux.O_TRUNC)
		}

		req, err := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), uint32(kernelTask.ThreadID()), i.NodeID, opcode, &in)
		if err != nil {
			return nil, err
		}

		// Send the request and receive the reply.
		res, err := i.fs.conn.Call(kernelTask, req)
		if err != nil {
			return nil, err
		}
		if err := res.Error(); err == syserror.ENOSYS && !isDir {
			i.fs.conn.noOpen = true
		} else if err != nil {
			return nil, err
		} else {
			out := linux.FUSEOpenOut{}
			if err := res.UnmarshalPayload(&out); err != nil {
				return nil, err
			}

			// Process the reply.
			fd.OpenFlag = out.OpenFlag
			if isDir {
				fd.OpenFlag &= ^uint32(linux.FOPEN_DIRECT_IO)
			}

			fd.Fh = out.Fh
		}
	}

	// TODO(gvisor.dev/issue/3234): invalidate mmap after implemented it for FUSE Inode
	fd.DirectIO = fd.OpenFlag&linux.FOPEN_DIRECT_IO != 0
	fdOptions := &vfs.FileDescriptionOptions{}
	if fd.OpenFlag&linux.FOPEN_NONSEEKABLE != 0 {
		fdOptions.DenyPRead = true
		fdOptions.DenyPWrite = true
		fd.Nonseekable = true
	}

	// If we don't send SETATTR before open (which is indicated by atomicOTrunc)
	// and O_TRUNC is set, update the inode's version number and clean existing data
	// by setting the file size to 0.
	if i.fs.conn.atomicOTrunc && opts.Flags&linux.O_TRUNC != 0 {
		i.fs.conn.mu.Lock()
		i.fs.conn.attributeVersion++
		i.attributeVersion = i.fs.conn.attributeVersion
		i.size = 0
		i.fs.conn.mu.Unlock()
		i.attributeTime = 0
	}

	if err := fd.vfsfd.Init(fdImpl, opts.Flags, rp.Mount(), vfsd, fdOptions); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

func (i *inode) Lookup(ctx context.Context, name string) (*vfs.Dentry, error) {
	in := linux.FUSELookupIn{Name: name}
	return i.newEntry(ctx, name, 0, linux.FUSE_LOOKUP, &in)
}

// IterDirents implements Inode.IterDirents.
func (inode) IterDirents(ctx context.Context, callback vfs.IterDirentsCallback, offset, relOffset int64) (int64, error) {
	return offset, nil
}

// Valid implements Inode.Valid.
func (inode) Valid(ctx context.Context) bool {
	return true
}

// NewNode implements kernfs.Inode.NewNode.
func (i *inode) NewNode(ctx context.Context, name string, opts vfs.MknodOptions) (*vfs.Dentry, error) {
	in := linux.FUSEMknodIn{
		MknodMeta: linux.FUSEMknodMeta{
			Mode:  uint32(opts.Mode),
			Rdev:  (opts.DevMinor & 0xff) | (opts.DevMajor << 8) | (opts.DevMinor & ^uint32((0xff)) << 12),
			Umask: uint32(kernel.TaskFromContext(ctx).FSContext().Umask()),
		},
		Name: name,
	}
	return i.newEntry(ctx, name, opts.Mode.FileType(), linux.FUSE_MKNOD, &in)
}

// NewSymlink implements kernfs.Inode.NewSymlink.
func (i *inode) NewSymlink(ctx context.Context, name, target string) (*vfs.Dentry, error) {
	in := linux.FUSESymLinkIn{
		Name:   name,
		Target: target,
	}
	return i.newEntry(ctx, name, linux.S_IFLNK, linux.FUSE_SYMLINK, &in)
}

// NewDir implements kernfs.Inode.NewDir.
func (i *inode) NewDir(ctx context.Context, name string, opts vfs.MkdirOptions) (*vfs.Dentry, error) {
	in := linux.FUSEMkdirIn{
		MkdirMeta: linux.FUSEMkdirMeta{
			Mode:  uint32(opts.Mode),
			Umask: uint32(kernel.TaskFromContext(ctx).FSContext().Umask()),
		},
		Name: name,
	}
	return i.newEntry(ctx, name, linux.S_IFDIR, linux.FUSE_MKDIR, &in)
}

// newEntry calls FUSE server for entry creation and allocates corresponding entry according to response.
// Shared by FUSE_MKNOD, FUSE_MKDIR, FUSE_SYMLINK, FUSE_LINK and inode.Lookup.
func (i *inode) newEntry(ctx context.Context, name string, fileType linux.FileMode, opcode linux.FUSEOpcode, payload marshal.Marshallable) (*vfs.Dentry, error) {
	kernelTask := kernel.TaskFromContext(ctx)
	if kernelTask == nil {
		log.Warningf("fusefs.Inode.newEntry: couldn't get kernel task from context", i.NodeID)
		return nil, syserror.EINVAL
	}
	req, err := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), uint32(kernelTask.ThreadID()), i.NodeID, opcode, payload)
	if err != nil {
		return nil, err
	}
	res, err := i.fs.conn.Call(kernelTask, req)
	if err != nil {
		return nil, err
	}
	if err := res.Error(); err != nil {
		return nil, err
	}
	out := linux.FUSEEntryOut{}
	if err := res.UnmarshalPayload(&out); err != nil {
		return nil, err
	}
	if opcode != linux.FUSE_LOOKUP && ((out.Attr.Mode&linux.S_IFMT)^uint32(fileType) != 0 || out.NodeID == 0 || out.NodeID == linux.FUSE_ROOT_ID) {
		return nil, syserror.EIO
	}
	child := i.fs.newInode(out.NodeID, out.Attr)
	i.dentry.InsertChildLocked(name, child)
	return child.VFSDentry(), nil
}

// Readlink implements Inode.Readlink.
func (i *inode) Readlink(ctx context.Context, mnt *vfs.Mount) (string, error) {
	if i.Mode().FileType()&linux.S_IFLNK == 0 {
		return "", syserror.EINVAL
	}
	if i.link == "" {
		kernelTask := kernel.TaskFromContext(ctx)
		if kernelTask == nil {
			log.Warningf("fusefs.Inode.Readlink: couldn't get kernel task from context")
			return "", syserror.EINVAL
		}
		req, err := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), uint32(kernelTask.ThreadID()), i.NodeID, linux.FUSE_READLINK, &linux.FUSEEmptyIn{})
		if err != nil {
			return "", err
		}
		res, err := i.fs.conn.Call(kernelTask, req)
		if err != nil {
			return "", err
		}
		i.link = string(res.data[res.hdr.SizeBytes():])
		if !mnt.Options().ReadOnly {
			i.attributeTime = 0
		}
	}
	return i.link, nil
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

// Stat implements kernfs.Inode.Stat.
func (i *inode) Stat(ctx context.Context, fs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	fusefs := fs.Impl().(*filesystem)
	conn := fusefs.conn
	task, creds := kernel.TaskFromContext(ctx), auth.CredentialsFromContext(ctx)
	if task == nil {
		log.Warningf("couldn't get kernel task from context")
		return linux.Statx{}, syserror.EINVAL
	}

	var in linux.FUSEGetAttrIn
	// We don't set any attribute in the request, because in VFS2 fstat(2) will
	// finally be translated into vfs.FilesystemImpl.StatAt() (see
	// pkg/sentry/syscalls/linux/vfs2/stat.go), resulting in the same flow
	// as stat(2). Thus GetAttrFlags and Fh variable will never be used in VFS2.
	req, err := conn.NewRequest(creds, uint32(task.ThreadID()), i.NodeID, linux.FUSE_GETATTR, &in)
	if err != nil {
		return linux.Statx{}, err
	}

	res, err := conn.Call(task, req)
	if err != nil {
		return linux.Statx{}, err
	}
	if err := res.Error(); err != nil {
		return linux.Statx{}, err
	}

	var out linux.FUSEGetAttrOut
	if err := res.UnmarshalPayload(&out); err != nil {
		return linux.Statx{}, err
	}

	// Set all metadata into kernfs.InodeAttrs.
	if err := i.SetStat(ctx, fs, creds, vfs.SetStatOptions{
		Stat: statFromFUSEAttr(out.Attr, linux.STATX_ALL, fusefs.devMinor),
	}); err != nil {
		return linux.Statx{}, err
	}

	return statFromFUSEAttr(out.Attr, opts.Mask, fusefs.devMinor), nil
}

// DecRef implements kernfs.Inode.
func (i *inode) DecRef(context.Context) {
	i.inodeRefs.DecRef(i.Destroy)
}
