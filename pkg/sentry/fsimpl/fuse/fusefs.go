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
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Name is the default filesystem name.
const Name = "fuse"

// maxActiveRequestsDefault is the default setting controlling the upper bound
// on the number of active requests at any given time.
const maxActiveRequestsDefault = 10000

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

// +stateify savable
type filesystemOptions struct {
	// mopts contains the raw, unparsed mount options passed to this filesystem.
	mopts string

	// uid of the mount owner.
	uid auth.KUID

	// gid of the mount owner.
	gid auth.KGID

	// rootMode specifies the the file mode of the filesystem's root.
	rootMode linux.FileMode

	// maxActiveRequests specifies the maximum number of active requests that can
	// exist at any time. Any further requests will block when trying to
	// Call the server.
	maxActiveRequests uint64

	// maxRead is the max number of bytes to read,
	// specified as "max_read" in fs parameters.
	// If not specified by user, use math.MaxUint32 as default value.
	maxRead uint32

	// defaultPermissions is the default_permissions mount option. It instructs
	// the kernel to perform a standard unix permission checks based on
	// ownership and mode bits, instead of deferring the check to the server.
	//
	// Immutable after mount.
	defaultPermissions bool

	// allowOther is the allow_other mount option. It allows processes that
	// don't own the FUSE mount to call into it.
	//
	// Immutable after mount.
	allowOther bool
}

// filesystem implements vfs.FilesystemImpl.
//
// +stateify savable
type filesystem struct {
	kernfs.Filesystem
	devMinor uint32

	// conn is used for communication between the FUSE server
	// daemon and the sentry fusefs.
	conn *connection

	// opts is the options the fusefs is initialized with.
	opts *filesystemOptions

	// umounted is true if filesystem.Release() has been called.
	umounted bool
}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fsType FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}

	fsopts := filesystemOptions{mopts: opts.Data}
	mopts := vfs.GenericParseMountOptions(opts.Data)
	deviceDescriptorStr, ok := mopts["fd"]
	if !ok {
		ctx.Warningf("fusefs.FilesystemType.GetFilesystem: mandatory mount option fd missing")
		return nil, nil, linuxerr.EINVAL
	}
	delete(mopts, "fd")

	deviceDescriptor, err := strconv.ParseInt(deviceDescriptorStr, 10 /* base */, 32 /* bitSize */)
	if err != nil {
		ctx.Debugf("fusefs.FilesystemType.GetFilesystem: invalid fd: %q (%v)", deviceDescriptorStr, err)
		return nil, nil, linuxerr.EINVAL
	}

	kernelTask := kernel.TaskFromContext(ctx)
	if kernelTask == nil {
		log.Warningf("%s.GetFilesystem: couldn't get kernel task from context", fsType.Name())
		return nil, nil, linuxerr.EINVAL
	}
	fuseFDGeneric := kernelTask.GetFileVFS2(int32(deviceDescriptor))
	if fuseFDGeneric == nil {
		return nil, nil, linuxerr.EINVAL
	}
	defer fuseFDGeneric.DecRef(ctx)
	fuseFD, ok := fuseFDGeneric.Impl().(*DeviceFD)
	if !ok {
		log.Warningf("%s.GetFilesystem: device FD is %T, not a FUSE device", fsType.Name, fuseFDGeneric)
		return nil, nil, linuxerr.EINVAL
	}

	// Parse and set all the other supported FUSE mount options.
	// TODO(gVisor.dev/issue/3229): Expand the supported mount options.
	if uidStr, ok := mopts["user_id"]; ok {
		delete(mopts, "user_id")
		uid, err := strconv.ParseUint(uidStr, 10, 32)
		if err != nil {
			log.Warningf("%s.GetFilesystem: invalid user_id: user_id=%s", fsType.Name(), uidStr)
			return nil, nil, linuxerr.EINVAL
		}
		kuid := creds.UserNamespace.MapToKUID(auth.UID(uid))
		if !kuid.Ok() {
			ctx.Warningf("fusefs.FilesystemType.GetFilesystem: unmapped uid: %d", uid)
			return nil, nil, linuxerr.EINVAL
		}
		fsopts.uid = kuid
	} else {
		ctx.Warningf("fusefs.FilesystemType.GetFilesystem: mandatory mount option user_id missing")
		return nil, nil, linuxerr.EINVAL
	}

	if gidStr, ok := mopts["group_id"]; ok {
		delete(mopts, "group_id")
		gid, err := strconv.ParseUint(gidStr, 10, 32)
		if err != nil {
			log.Warningf("%s.GetFilesystem: invalid group_id: group_id=%s", fsType.Name(), gidStr)
			return nil, nil, linuxerr.EINVAL
		}
		kgid := creds.UserNamespace.MapToKGID(auth.GID(gid))
		if !kgid.Ok() {
			ctx.Warningf("fusefs.FilesystemType.GetFilesystem: unmapped gid: %d", gid)
			return nil, nil, linuxerr.EINVAL
		}
		fsopts.gid = kgid
	} else {
		ctx.Warningf("fusefs.FilesystemType.GetFilesystem: mandatory mount option group_id missing")
		return nil, nil, linuxerr.EINVAL
	}

	if modeStr, ok := mopts["rootmode"]; ok {
		delete(mopts, "rootmode")
		mode, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil {
			log.Warningf("%s.GetFilesystem: invalid mode: %q", fsType.Name(), modeStr)
			return nil, nil, linuxerr.EINVAL
		}
		fsopts.rootMode = linux.FileMode(mode)
	} else {
		ctx.Warningf("fusefs.FilesystemType.GetFilesystem: mandatory mount option rootmode missing")
		return nil, nil, linuxerr.EINVAL
	}

	// Set the maxInFlightRequests option.
	fsopts.maxActiveRequests = maxActiveRequestsDefault

	if maxReadStr, ok := mopts["max_read"]; ok {
		delete(mopts, "max_read")
		maxRead, err := strconv.ParseUint(maxReadStr, 10, 32)
		if err != nil {
			log.Warningf("%s.GetFilesystem: invalid max_read: max_read=%s", fsType.Name(), maxReadStr)
			return nil, nil, linuxerr.EINVAL
		}
		if maxRead < fuseMinMaxRead {
			maxRead = fuseMinMaxRead
		}
		fsopts.maxRead = uint32(maxRead)
	} else {
		fsopts.maxRead = math.MaxUint32
	}

	if _, ok := mopts["default_permissions"]; ok {
		delete(mopts, "default_permissions")
		fsopts.defaultPermissions = true
	}

	if _, ok := mopts["allow_other"]; ok {
		delete(mopts, "allow_other")
		fsopts.allowOther = true
	}

	// Check for unparsed options.
	if len(mopts) != 0 {
		log.Warningf("%s.GetFilesystem: unsupported or unknown options: %v", fsType.Name(), mopts)
		return nil, nil, linuxerr.EINVAL
	}

	// Create a new FUSE filesystem.
	fs, err := newFUSEFilesystem(ctx, vfsObj, &fsType, fuseFD, devMinor, &fsopts)
	if err != nil {
		log.Warningf("%s.NewFUSEFilesystem: failed with error: %v", fsType.Name(), err)
		return nil, nil, err
	}

	// Send a FUSE_INIT request to the FUSE daemon server before returning.
	// This call is not blocking.
	if err := fs.conn.InitSend(creds, uint32(kernelTask.ThreadID())); err != nil {
		log.Warningf("%s.InitSend: failed with error: %v", fsType.Name(), err)
		fs.VFSFilesystem().DecRef(ctx) // returned by newFUSEFilesystem
		return nil, nil, err
	}

	// root is the fusefs root directory.
	root := fs.newRoot(ctx, creds, fsopts.rootMode)

	return fs.VFSFilesystem(), root.VFSDentry(), nil
}

// newFUSEFilesystem creates a new FUSE filesystem.
func newFUSEFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, fsType *FilesystemType, fuseFD *DeviceFD, devMinor uint32, opts *filesystemOptions) (*filesystem, error) {
	conn, err := newFUSEConnection(ctx, fuseFD, opts)
	if err != nil {
		log.Warningf("fuse.NewFUSEFilesystem: NewFUSEConnection failed with error: %v", err)
		return nil, linuxerr.EINVAL
	}

	fs := &filesystem{
		devMinor: devMinor,
		opts:     opts,
		conn:     conn,
	}
	fs.VFSFilesystem().Init(vfsObj, fsType, fs)

	// FIXME(gvisor.dev/issue/4813): Doesn't conn or fs need to hold a
	// reference on fuseFD, since conn uses fuseFD for communication with the
	// server? Wouldn't doing so create a circular reference?
	fs.VFSFilesystem().IncRef() // for fuseFD.fs
	// FIXME(gvisor.dev/issue/4813): fuseFD.fs is accessed without
	// synchronization.
	fuseFD.fs = fs

	return fs, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.conn.fd.mu.Lock()

	fs.umounted = true
	fs.conn.Abort(ctx)
	// Notify all the waiters on this fd.
	fs.conn.fd.waitQueue.Notify(waiter.ReadableEvents)

	fs.conn.fd.mu.Unlock()

	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release(ctx)
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return fs.opts.mopts
}

// inode implements kernfs.Inode.
//
// +stateify savable
type inode struct {
	inodeRefs
	kernfs.InodeAlwaysValid
	kernfs.InodeAttrs
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeNotSymlink
	kernfs.OrderedChildren

	// the owning filesystem. fs is immutable.
	fs *filesystem

	// metaDataMu protects the metadata of this inode.
	metadataMu sync.Mutex

	nodeID uint64

	locks vfs.FileLocks

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

func (fs *filesystem) newRoot(ctx context.Context, creds *auth.Credentials, mode linux.FileMode) *kernfs.Dentry {
	i := &inode{fs: fs, nodeID: 1}
	i.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, 1, linux.ModeDirectory|0755)
	i.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	i.InitRefs()

	var d kernfs.Dentry
	d.InitRoot(&fs.Filesystem, i)
	return &d
}

func (fs *filesystem) newInode(ctx context.Context, nodeID uint64, attr linux.FUSEAttr) kernfs.Inode {
	i := &inode{fs: fs, nodeID: nodeID}
	creds := auth.Credentials{EffectiveKGID: auth.KGID(attr.UID), EffectiveKUID: auth.KUID(attr.UID)}
	i.InodeAttrs.Init(ctx, &creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.FileMode(attr.Mode))
	atomic.StoreUint64(&i.size, attr.Size)
	i.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	i.InitRefs()
	return i
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
	if i.fs.opts.defaultPermissions {
		return i.InodeAttrs.CheckPermissions(ctx, creds, ats)
	}
	return nil
}

// Open implements kernfs.Inode.Open.
func (i *inode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	isDir := i.InodeAttrs.Mode().IsDir()
	// return error if specified to open directory but inode is not a directory.
	if !isDir && opts.Mode.IsDir() {
		return nil, linuxerr.ENOTDIR
	}
	if opts.Flags&linux.O_LARGEFILE == 0 && atomic.LoadUint64(&i.size) > linux.MAX_NON_LFS {
		return nil, linuxerr.EOVERFLOW
	}

	var fd *fileDescription
	var fdImpl vfs.FileDescriptionImpl
	if isDir {
		directoryFD := &directoryFD{}
		fd = &(directoryFD.fileDescription)
		fdImpl = directoryFD
	} else {
		regularFD := &regularFileFD{}
		fd = &(regularFD.fileDescription)
		fdImpl = regularFD
	}
	// FOPEN_KEEP_CACHE is the defualt flag for noOpen.
	fd.OpenFlag = linux.FOPEN_KEEP_CACHE

	// Only send open request when FUSE server support open or is opening a directory.
	if !i.fs.conn.noOpen || isDir {
		kernelTask := kernel.TaskFromContext(ctx)
		if kernelTask == nil {
			log.Warningf("fusefs.Inode.Open: couldn't get kernel task from context")
			return nil, linuxerr.EINVAL
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

		// Send the request and receive the reply.
		req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), uint32(kernelTask.ThreadID()), i.nodeID, opcode, &in)
		res, err := i.fs.conn.Call(kernelTask, req)
		if err != nil {
			return nil, err
		}
		if err := res.Error(); linuxerr.Equals(linuxerr.ENOSYS, err) && !isDir {
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
		atomic.StoreUint64(&i.size, 0)
		i.fs.conn.mu.Unlock()
		i.attributeTime = 0
	}

	if err := fd.vfsfd.Init(fdImpl, opts.Flags, rp.Mount(), d.VFSDentry(), fdOptions); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Lookup implements kernfs.Inode.Lookup.
func (i *inode) Lookup(ctx context.Context, name string) (kernfs.Inode, error) {
	in := linux.FUSELookupIn{Name: name}
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
	kernelTask := kernel.TaskFromContext(ctx)
	if kernelTask == nil {
		log.Warningf("fusefs.Inode.NewFile: couldn't get kernel task from context", i.nodeID)
		return nil, linuxerr.EINVAL
	}
	in := linux.FUSECreateIn{
		CreateMeta: linux.FUSECreateMeta{
			Flags: opts.Flags,
			Mode:  uint32(opts.Mode) | linux.S_IFREG,
			Umask: uint32(kernelTask.FSContext().Umask()),
		},
		Name: name,
	}
	return i.newEntry(ctx, name, linux.S_IFREG, linux.FUSE_CREATE, &in)
}

// NewNode implements kernfs.Inode.NewNode.
func (i *inode) NewNode(ctx context.Context, name string, opts vfs.MknodOptions) (kernfs.Inode, error) {
	in := linux.FUSEMknodIn{
		MknodMeta: linux.FUSEMknodMeta{
			Mode:  uint32(opts.Mode),
			Rdev:  linux.MakeDeviceID(uint16(opts.DevMajor), opts.DevMinor),
			Umask: uint32(kernel.TaskFromContext(ctx).FSContext().Umask()),
		},
		Name: name,
	}
	return i.newEntry(ctx, name, opts.Mode.FileType(), linux.FUSE_MKNOD, &in)
}

// NewSymlink implements kernfs.Inode.NewSymlink.
func (i *inode) NewSymlink(ctx context.Context, name, target string) (kernfs.Inode, error) {
	in := linux.FUSESymLinkIn{
		Name:   name,
		Target: target,
	}
	return i.newEntry(ctx, name, linux.S_IFLNK, linux.FUSE_SYMLINK, &in)
}

// Unlink implements kernfs.Inode.Unlink.
func (i *inode) Unlink(ctx context.Context, name string, child kernfs.Inode) error {
	kernelTask := kernel.TaskFromContext(ctx)
	if kernelTask == nil {
		log.Warningf("fusefs.Inode.newEntry: couldn't get kernel task from context", i.nodeID)
		return linuxerr.EINVAL
	}
	in := linux.FUSEUnlinkIn{Name: name}
	req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), uint32(kernelTask.ThreadID()), i.nodeID, linux.FUSE_UNLINK, &in)
	res, err := i.fs.conn.Call(kernelTask, req)
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
			Umask: uint32(kernel.TaskFromContext(ctx).FSContext().Umask()),
		},
		Name: name,
	}
	return i.newEntry(ctx, name, linux.S_IFDIR, linux.FUSE_MKDIR, &in)
}

// RmDir implements kernfs.Inode.RmDir.
func (i *inode) RmDir(ctx context.Context, name string, child kernfs.Inode) error {
	fusefs := i.fs
	task, creds := kernel.TaskFromContext(ctx), auth.CredentialsFromContext(ctx)

	in := linux.FUSERmDirIn{Name: name}
	req := fusefs.conn.NewRequest(creds, uint32(task.ThreadID()), i.nodeID, linux.FUSE_RMDIR, &in)
	res, err := i.fs.conn.Call(task, req)
	if err != nil {
		return err
	}
	return res.Error()
}

// newEntry calls FUSE server for entry creation and allocates corresponding entry according to response.
// Shared by FUSE_MKNOD, FUSE_MKDIR, FUSE_SYMLINK, FUSE_LINK and FUSE_LOOKUP.
func (i *inode) newEntry(ctx context.Context, name string, fileType linux.FileMode, opcode linux.FUSEOpcode, payload marshal.Marshallable) (kernfs.Inode, error) {
	kernelTask := kernel.TaskFromContext(ctx)
	if kernelTask == nil {
		log.Warningf("fusefs.Inode.newEntry: couldn't get kernel task from context", i.nodeID)
		return nil, linuxerr.EINVAL
	}
	req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), uint32(kernelTask.ThreadID()), i.nodeID, opcode, payload)
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
		return nil, linuxerr.EIO
	}
	child := i.fs.newInode(ctx, out.NodeID, out.Attr)
	return child, nil
}

// Getlink implements kernfs.Inode.Getlink.
func (i *inode) Getlink(ctx context.Context, mnt *vfs.Mount) (vfs.VirtualDentry, string, error) {
	path, err := i.Readlink(ctx, mnt)
	return vfs.VirtualDentry{}, path, err
}

// Readlink implements kernfs.Inode.Readlink.
func (i *inode) Readlink(ctx context.Context, mnt *vfs.Mount) (string, error) {
	if i.Mode().FileType()&linux.S_IFLNK == 0 {
		return "", linuxerr.EINVAL
	}
	if len(i.link) == 0 {
		kernelTask := kernel.TaskFromContext(ctx)
		if kernelTask == nil {
			log.Warningf("fusefs.Inode.Readlink: couldn't get kernel task from context")
			return "", linuxerr.EINVAL
		}
		req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), uint32(kernelTask.ThreadID()), i.nodeID, linux.FUSE_READLINK, &linux.FUSEEmptyIn{})
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

// getFUSEAttr returns a linux.FUSEAttr of this inode stored in local cache.
// TODO(gvisor.dev/issue/3679): Add support for other fields.
func (i *inode) getFUSEAttr() linux.FUSEAttr {
	return linux.FUSEAttr{
		Ino:  i.Ino(),
		Size: atomic.LoadUint64(&i.size),
		Mode: uint32(i.Mode()),
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
func (i *inode) getAttr(ctx context.Context, fs *vfs.Filesystem, opts vfs.StatOptions, flags uint32, fh uint64) (linux.FUSEAttr, error) {
	attributeVersion := atomic.LoadUint64(&i.fs.conn.attributeVersion)

	// TODO(gvisor.dev/issue/3679): send the request only if
	// - invalid local cache for fields specified in the opts.Mask
	// - forced update
	// - i.attributeTime expired
	// If local cache is still valid, return local cache.
	// Currently we always send a request,
	// and we always set the metadata with the new result,
	// unless attributeVersion has changed.

	task := kernel.TaskFromContext(ctx)
	if task == nil {
		log.Warningf("couldn't get kernel task from context")
		return linux.FUSEAttr{}, linuxerr.EINVAL
	}

	creds := auth.CredentialsFromContext(ctx)

	in := linux.FUSEGetAttrIn{
		GetAttrFlags: flags,
		Fh:           fh,
	}
	req := i.fs.conn.NewRequest(creds, uint32(task.ThreadID()), i.nodeID, linux.FUSE_GETATTR, &in)
	res, err := i.fs.conn.Call(task, req)
	if err != nil {
		return linux.FUSEAttr{}, err
	}
	if err := res.Error(); err != nil {
		return linux.FUSEAttr{}, err
	}

	var out linux.FUSEGetAttrOut
	if err := res.UnmarshalPayload(&out); err != nil {
		return linux.FUSEAttr{}, err
	}

	// Local version is newer, return the local one.
	// Skip the update.
	if attributeVersion != 0 && atomic.LoadUint64(&i.attributeVersion) > attributeVersion {
		return i.getFUSEAttr(), nil
	}

	// Set the metadata of kernfs.InodeAttrs.
	if err := i.InodeAttrs.SetStat(ctx, fs, creds, vfs.SetStatOptions{
		Stat: statFromFUSEAttr(out.Attr, linux.STATX_ALL, i.fs.devMinor),
	}); err != nil {
		return linux.FUSEAttr{}, err
	}

	// Set the size if no error (after SetStat() check).
	atomic.StoreUint64(&i.size, out.Attr.Size)

	return out.Attr, nil
}

// reviseAttr attempts to update the attributes for internal purposes
// by calling getAttr with a pre-specified mask.
// Used by read, write, lseek.
func (i *inode) reviseAttr(ctx context.Context, flags uint32, fh uint64) error {
	// Never need atime for internal purposes.
	_, err := i.getAttr(ctx, i.fs.VFSFilesystem(), vfs.StatOptions{
		Mask: linux.STATX_BASIC_STATS &^ linux.STATX_ATIME,
	}, flags, fh)
	return err
}

// Stat implements kernfs.Inode.Stat.
func (i *inode) Stat(ctx context.Context, fs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
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
	// TODO(gvisor.dev/issues/3413): Complete the implementation of statfs.
	return vfs.GenericStatFS(linux.FUSE_SUPER_MAGIC), nil
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
	return i.setAttr(ctx, fs, creds, opts, false, 0)
}

func (i *inode) setAttr(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions, useFh bool, fh uint64) error {
	conn := i.fs.conn
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		log.Warningf("couldn't get kernel task from context")
		return linuxerr.EINVAL
	}

	// We should retain the original file type when assigning new mode.
	fileType := uint16(i.Mode()) & linux.S_IFMT
	fattrMask := fattrMaskFromStats(opts.Stat.Mask)
	if useFh {
		fattrMask |= linux.FATTR_FH
	}
	in := linux.FUSESetAttrIn{
		Valid:     fattrMask,
		Fh:        fh,
		Size:      opts.Stat.Size,
		Atime:     uint64(opts.Stat.Atime.Sec),
		Mtime:     uint64(opts.Stat.Mtime.Sec),
		Ctime:     uint64(opts.Stat.Ctime.Sec),
		AtimeNsec: opts.Stat.Atime.Nsec,
		MtimeNsec: opts.Stat.Mtime.Nsec,
		CtimeNsec: opts.Stat.Ctime.Nsec,
		Mode:      uint32(fileType | opts.Stat.Mode),
		UID:       opts.Stat.UID,
		GID:       opts.Stat.GID,
	}
	req := conn.NewRequest(creds, uint32(task.ThreadID()), i.nodeID, linux.FUSE_SETATTR, &in)
	res, err := conn.Call(task, req)
	if err != nil {
		return err
	}
	if err := res.Error(); err != nil {
		return err
	}
	out := linux.FUSEGetAttrOut{}
	if err := res.UnmarshalPayload(&out); err != nil {
		return err
	}

	// Set the metadata of kernfs.InodeAttrs.
	if err := i.InodeAttrs.SetStat(ctx, fs, creds, vfs.SetStatOptions{
		Stat: statFromFUSEAttr(out.Attr, linux.STATX_ALL, i.fs.devMinor),
	}); err != nil {
		return err
	}

	return nil
}
