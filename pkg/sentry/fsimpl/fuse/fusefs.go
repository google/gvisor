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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync/locking"
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

	// clock is a real-time clock used to set timestamps in file operations.
	clock time.Clock
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
	fuseFDGeneric := kernelTask.GetFile(int32(deviceDescriptor))
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

	fuseFD.mu.Lock()
	connected := fuseFD.connected()
	// Create a new FUSE filesystem.
	fs, err := newFUSEFilesystem(ctx, vfsObj, &fsType, fuseFD, devMinor, &fsopts)
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

	// root is the fusefs root directory.
	root := fs.newRoot(ctx, creds, fsopts.rootMode)

	return fs.VFSFilesystem(), root.VFSDentry(), nil
}

var lockClassGenerator = locking.NewLockClassGenerator("fusefs")

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
		clock:    time.RealtimeClockFromContext(ctx),
	}
	fs.Init(lockClassGenerator)
	fs.VFSFilesystem().Init(vfsObj, fsType, fs)
	return fs, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
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

func (fs *filesystem) newInode(ctx context.Context, nodeID uint64, attr linux.FUSEAttr) kernfs.Inode {
	i := &inode{fs: fs, nodeID: nodeID}
	creds := auth.Credentials{EffectiveKGID: auth.KGID(attr.UID), EffectiveKUID: auth.KUID(attr.UID)}
	i.attrMu.Lock()
	i.init(&creds, linux.UNNAMED_MAJOR, fs.devMinor, nodeID, linux.FileMode(attr.Mode), attr.Nlink)
	i.size.Store(attr.Size)
	i.attrMu.Unlock()
	i.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	i.InitRefs()
	return i
}
