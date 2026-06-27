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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
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

	// rootMode specifies the file mode of the filesystem's root.
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
	// daemon and the sentry fusefs. It holds shared protocol state and
	// delegates call dispatch to its internal fuseConn transport.
	conn *connection

	// opts is the options the fusefs is initialized with.
	opts *filesystemOptions

	// clock is a real-time clock used to set timestamps in file operations.
	clock ktime.Clock
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

	fsopts, fd, err := parseOptions(ctx, creds, opts.Data)
	if err != nil {
		return nil, nil, err
	}

	kernelTask := kernel.TaskFromContext(ctx)
	if kernelTask == nil {
		log.Warningf("%s.GetFilesystem: couldn't get kernel task from context", fsType.Name())
		return nil, nil, linuxerr.EINVAL
	}

	fuseFDGeneric := kernelTask.GetFile(fd)
	if fuseFDGeneric == nil {
		return nil, nil, linuxerr.EINVAL
	}
	defer fuseFDGeneric.DecRef(ctx)
	fuseFD, ok := fuseFDGeneric.Impl().(*DeviceFD)
	if ok {
		return fsType.getFilesystemDeviceFD(ctx, vfsObj, creds, kernelTask, fuseFD, devMinor, fsopts)
	}

	// Check if this is a host FD. Try the file description first (for
	// regular files, pipes), then the dentry inode (for sockets, which
	// have a different file description type but the same host inode).
	rawHostFD := -1
	if hfd, ok := fuseFDGeneric.Impl().(vfs.HostFDProvider); ok {
		rawHostFD = hfd.HostFD()
	} else if d := fuseFDGeneric.Dentry(); d != nil {
		if kd, ok := d.Impl().(*kernfs.Dentry); ok {
			if hfd, ok := kd.Inode().(vfs.HostFDProvider); ok {
				rawHostFD = hfd.HostFD()
			}
		}
	}
	if rawHostFD == -1 {
		log.Warningf("%s.GetFilesystem: fd is %T, not a FUSE device or host FD", fsType.Name(), fuseFDGeneric.Impl())
		return nil, nil, linuxerr.EINVAL
	}

	return fsType.getFilesystemHostFD(ctx, vfsObj, creds, kernelTask, int32(rawHostFD), devMinor, fsopts)
}

// getFilesystemDeviceFD creates a FUSE filesystem backed by an in-sandbox
// /dev/fuse DeviceFD.
func (fsType FilesystemType) getFilesystemDeviceFD(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, kernelTask *kernel.Task, fuseFD *DeviceFD, devMinor uint32, fsopts *filesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	fuseFD.mu.Lock()
	connected := fuseFD.connected()
	fs, err := newFUSEFilesystem(ctx, vfsObj, &fsType, fuseFD, devMinor, fsopts)
	if err != nil {
		log.Warningf("%s.NewFUSEFilesystem: failed with error: %v", fsType.Name(), err)
		fuseFD.mu.Unlock()
		return nil, nil, err
	}
	fuseFD.mu.Unlock()

	// Send a FUSE_INIT request to the FUSE daemon server before returning.
	// This call is not blocking.
	if !connected {
		if err := fs.conn.InitSend(creds, uint32(kernelTask.ThreadID())); err != nil {
			log.Warningf("%s.InitSend: failed with error: %v", fsType.Name(), err)
			return nil, nil, err
		}
	}

	root := fs.newRoot(ctx, creds, fsopts.rootMode)
	return fs.VFSFilesystem(), root.VFSDentry(), nil
}

// getFilesystemHostFD creates a FUSE filesystem that communicates with a FUSE
// server running on the host via a host file descriptor.
func (fsType FilesystemType) getFilesystemHostFD(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, kernelTask *kernel.Task, hostFD int32, devMinor uint32, fsopts *filesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	// Dup the host FD so that the FUSE connection owns its own copy.
	// The original may be shared with or closed by the host import path
	// (e.g. socket endpoints take ownership of the FD).
	dupFD, err := unix.Dup(int(hostFD))
	if err != nil {
		log.Warningf("%s.getFilesystemHostFD: dup failed: %v", fsType.Name(), err)
		return nil, nil, err
	}
	// The host import path sets the FD to non-blocking for epoll-based I/O.
	// The FUSE passthrough connection uses synchronous blocking I/O, so
	// clear the non-blocking flag.
	if err := unix.SetNonblock(dupFD, false); err != nil {
		unix.Close(dupFD)
		log.Warningf("%s.getFilesystemHostFD: SetNonblock failed: %v", fsType.Name(), err)
		return nil, nil, err
	}

	conn, err := newFUSEConnectionOpts(fsopts)
	if err != nil {
		unix.Close(dupFD)
		log.Warningf("%s.getFilesystemHostFD: newFUSEConnection failed: %v", fsType.Name(), err)
		return nil, nil, err
	}

	hostConn := newHostConnection(conn, int32(dupFD))
	conn.fuseConn = hostConn

	fs := &filesystem{
		devMinor: devMinor,
		opts:     fsopts,
		conn:     conn,
		clock:    ktime.RealtimeClockFromContext(ctx),
	}
	fs.VFSFilesystem().Init(vfsObj, &fsType, fs)

	rootUserNs := kernel.KernelFromContext(ctx).RootUserNamespace()
	hasSysAdmin := creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, rootUserNs)
	if err := hostConn.InitSend(creds, uint32(kernelTask.ThreadID()), hasSysAdmin); err != nil {
		log.Warningf("%s.getFilesystemHostFD: InitSend failed: %v", fsType.Name(), err)
		return nil, nil, err
	}

	root := fs.newRoot(ctx, creds, fsopts.rootMode)
	return fs.VFSFilesystem(), root.VFSDentry(), nil
}

func parseOptions(ctx context.Context, creds *auth.Credentials, data string) (*filesystemOptions, int32, error) {
	fsopts := &filesystemOptions{
		mopts:             data,
		maxActiveRequests: maxActiveRequestsDefault,
		maxRead:           math.MaxUint32,
	}

	mopts := vfs.GenericParseMountOptions(data)

	// Parse 'fd'.
	deviceDescriptorStr, ok := mopts["fd"]
	if !ok {
		ctx.Warningf("fusefs.FilesystemType.GetFilesystem: mandatory mount option fd missing")
		return nil, 0, linuxerr.EINVAL
	}
	delete(mopts, "fd")

	deviceDescriptor, err := strconv.ParseInt(deviceDescriptorStr, 10, 32)
	if err != nil {
		ctx.Debugf("fusefs.FilesystemType.GetFilesystem: invalid fd: %q (%v)", deviceDescriptorStr, err)
		return nil, 0, linuxerr.EINVAL
	}

	// Parse 'user_id'.
	if uidStr, ok := mopts["user_id"]; ok {
		delete(mopts, "user_id")
		uid, err := strconv.ParseUint(uidStr, 10, 32)
		if err != nil {
			log.Warningf("fusefs.parseOptions: invalid user_id: %s", uidStr)
			return nil, 0, linuxerr.EINVAL
		}
		kuid := creds.UserNamespace.MapToKUID(auth.UID(uid))
		if !kuid.Ok() {
			ctx.Warningf("fusefs.parseOptions: unmapped uid: %d", uid)
			return nil, 0, linuxerr.EINVAL
		}
		fsopts.uid = kuid
	} else {
		ctx.Warningf("fusefs.parseOptions: mandatory mount option user_id missing")
		return nil, 0, linuxerr.EINVAL
	}

	// Parse 'group_id'.
	if gidStr, ok := mopts["group_id"]; ok {
		delete(mopts, "group_id")
		gid, err := strconv.ParseUint(gidStr, 10, 32)
		if err != nil {
			log.Warningf("fusefs.parseOptions: invalid group_id: %s", gidStr)
			return nil, 0, linuxerr.EINVAL
		}
		kgid := creds.UserNamespace.MapToKGID(auth.GID(gid))
		if !kgid.Ok() {
			ctx.Warningf("fusefs.parseOptions: unmapped gid: %d", gid)
			return nil, 0, linuxerr.EINVAL
		}
		fsopts.gid = kgid
	} else {
		ctx.Warningf("fusefs.parseOptions: mandatory mount option group_id missing")
		return nil, 0, linuxerr.EINVAL
	}

	// Parse 'rootmode'.
	if modeStr, ok := mopts["rootmode"]; ok {
		delete(mopts, "rootmode")
		mode, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil {
			log.Warningf("fusefs.parseOptions: invalid mode: %q", modeStr)
			return nil, 0, linuxerr.EINVAL
		}
		fsopts.rootMode = linux.FileMode(mode)
	} else {
		ctx.Warningf("fusefs.parseOptions: mandatory mount option rootmode missing")
		return nil, 0, linuxerr.EINVAL
	}

	// Parse 'max_read'.
	if maxReadStr, ok := mopts["max_read"]; ok {
		delete(mopts, "max_read")
		maxRead, err := strconv.ParseUint(maxReadStr, 10, 32)
		if err != nil {
			log.Warningf("fusefs.parseOptions: invalid max_read: %s", maxReadStr)
			return nil, 0, linuxerr.EINVAL
		}
		if maxRead < fuseMinMaxRead {
			maxRead = fuseMinMaxRead
		}
		fsopts.maxRead = uint32(maxRead)
	}

	// Parse 'default_permissions'.
	if _, ok := mopts["default_permissions"]; ok {
		delete(mopts, "default_permissions")
		fsopts.defaultPermissions = true
	}

	// Parse 'allow_other'.
	if _, ok := mopts["allow_other"]; ok {
		delete(mopts, "allow_other")
		fsopts.allowOther = true
	}

	// Check for unparsed options.
	if len(mopts) != 0 {
		log.Warningf("fusefs.parseOptions: unsupported or unknown options: %v", mopts)
		return nil, 0, linuxerr.EINVAL
	}

	return fsopts, int32(deviceDescriptor), nil
}

// newFUSEFilesystem creates a new FUSE filesystem.
// +checklocks:fuseFD.mu
func newFUSEFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, fsType *FilesystemType, fuseFD *DeviceFD, devMinor uint32, opts *filesystemOptions) (*filesystem, error) {
	if !fuseFD.connected() {
		conn, err := newFUSEConnection(ctx, fuseFD, opts)
		if err != nil {
			log.Warningf("fuse.NewFUSEFilesystem: NewFUSEConnection failed with error: %v", err)
			return nil, linuxerr.EINVAL
		}
		fuseFD.conn = conn
	}

	fs := &filesystem{
		devMinor: devMinor,
		opts:     opts,
		conn:     fuseFD.conn,
		clock:    ktime.RealtimeClockFromContext(ctx),
	}
	fs.VFSFilesystem().Init(vfsObj, fsType, fs)
	return fs, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.conn.fuseConn.release(ctx)
	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release(ctx)
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return fs.opts.mopts
}

func (fs *filesystem) newRoot(ctx context.Context, creds *auth.Credentials, mode linux.FileMode) *kernfs.Dentry {
	i := &inode{fs: fs, nodeID: 1}
	i.attrMu.Lock()
	i.init(creds, linux.UNNAMED_MAJOR, fs.devMinor, 1, linux.ModeDirectory|0755, 2)
	i.attrMu.Unlock()
	i.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	i.InitRefs()

	var d kernfs.Dentry
	d.InitRoot(&fs.Filesystem, i)
	return &d
}

func (fs *filesystem) newInode(ctx context.Context, out linux.FUSEEntryOut) (kernfs.Inode, error) {
	attr := out.Attr
	if !isValidType(attr.Mode) {
		return nil, linuxerr.EIO
	}
	i := &inode{fs: fs, nodeID: out.NodeID, generation: out.Generation}
	i.attrMu.Lock()
	defer i.attrMu.Unlock()

	creds := auth.Credentials{EffectiveKGID: auth.KGID(attr.UID), EffectiveKUID: auth.KUID(attr.UID)}
	i.init(&creds, linux.UNNAMED_MAJOR, fs.devMinor, out.NodeID, linux.FileMode(attr.Mode), attr.Nlink)
	i.updateAttrs(attr, int64(out.AttrValid), int64(out.AttrValidNSec))
	i.updateEntryTime(int64(out.EntryValid), int64(out.EntryValidNSec))

	i.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	i.InitRefs()
	return i, nil
}

// isValidType is analogous to fs/fuse/dir.c:fuse_valid_type().
func isValidType(mode uint32) bool {
	switch mode & linux.S_IFMT {
	case linux.S_IFREG, linux.S_IFDIR, linux.S_IFLNK, linux.S_IFCHR, linux.S_IFBLK, linux.S_IFIFO, linux.S_IFSOCK:
		return true
	default:
		return false
	}
}
