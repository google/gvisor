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

package gofer

import (
	"fmt"
	"math"
	"path"
	"path/filepath"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fsutil"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// LINT.IfChange

const (
	hostOpenFlags = unix.O_NOFOLLOW | unix.O_CLOEXEC
)

// tryOpen tries to open() with different modes in the following order:
//  1. RDONLY | NONBLOCK: for all files, directories, ro mounts, FIFOs.
//     Use non-blocking to prevent getting stuck inside open(2) for
//     FIFOs. This option has no effect on regular files.
//  2. PATH: for symlinks, sockets.
func tryOpen(open func(int) (int, error)) (int, error) {
	flags := []int{
		unix.O_RDONLY | unix.O_NONBLOCK,
		unix.O_PATH,
	}

	var (
		hostFD int
		err    error
	)
	for _, flag := range flags {
		hostFD, err = open(flag | hostOpenFlags)
		if err == nil {
			return hostFD, nil
		}

		if err == unix.ENOENT {
			// File doesn't exist, no point in retrying.
			break
		}
	}
	return -1, err
}

// getDirectfsRootInode creates a new inode representing the root inode for
// this mountpoint. getDirectfsRootInode takes ownership of rootHostFD and
// rootControlFD.
func (fs *filesystem) getDirectfsRootInode(ctx context.Context, rootHostFD int, rootControlFD lisafs.ClientFD) (*inode, error) {
	inode, err := fs.newDirectfsInode(rootHostFD)
	if err != nil {
		log.Warningf("newDirectfsInode failed for mount point dentry: %v", err)
		rootControlFD.Close(ctx, false /* flush */)
		return nil, err
	}
	inode.impl.(*directfsInode).controlFDLisa = rootControlFD
	return inode, nil
}

// directfsInode is a host dentry implementation. It represents a dentry
// backed by a host file descriptor. All operations are directly performed on
// the host. A gofer is only involved for some operations on the mount point
// dentry (when dentry.parent = nil). We are forced to fall back to the gofer
// due to the lack of procfs in the sandbox process.
//
// +stateify savable
type directfsInode struct {
	inode

	// controlFD is the host FD to this file. controlFD is immutable until
	// destruction, which is synchronized with dentry.handleMu.
	controlFD int

	// controlFDLisa is a lisafs control FD on this dentry.
	// This is used to fallback to using lisafs RPCs in the following cases:
	// * When parent dentry is required to perform operations but
	//   dentry.parent = nil (root dentry).
	// * For path-based syscalls (like connect(2) and bind(2)) on sockets.
	//
	// For the root dentry, controlFDLisa is always set and is immutable.
	// For sockets, controlFDLisa is protected by dentry.handleMu and is
	// immutable after initialization.
	controlFDLisa lisafs.ClientFD `state:"nosave"`
}

// newDirectfsInode creates a new dentry representing the given file. The dentry
// initially has no references, but is not cached; it is the caller's
// responsibility to set the dentry's reference count and/or call
// dentry.checkCachingLocked() as appropriate.
// newDirectDentry takes ownership of controlFD.
func (fs *filesystem) newDirectfsInode(controlFD int) (*inode, error) {
	var stat unix.Stat_t
	var ret *inode = nil
	if err := unix.Fstat(controlFD, &stat); err != nil {
		log.Warningf("failed to fstat(2) FD %d: %v", controlFD, err)
		_ = unix.Close(controlFD)
		return nil, err
	}
	inoKey := inoKeyFromStat(&stat)

	if fs.opts.enableInodeSharing {
		cachedInode := fs.findInode(inoKey)
		if cachedInode != nil {
			ret = cachedInode
		}
	}

	if ret == nil {
		i := &directfsInode{
			inode:     inode{},
			controlFD: controlFD,
		}

		// Initalize the inode before use or setting fields
		i.init(fs, fs.inoFromKey(inoKey), &inoKey, i)
		ret = &i.inode
		ret.nlink.Store(uint32(stat.Nlink))
		ret.mode.Store(uint32(stat.Mode))
		ret.uid.Store(uint32(stat.Uid))
		ret.gid.Store(uint32(stat.Gid))
		ret.size.Store(uint64(stat.Size))
		ret.blockSize.Store(uint32(stat.Blksize))
		ret.atime.Store(dentryTimestampFromUnix(stat.Atim))
		ret.mtime.Store(dentryTimestampFromUnix(stat.Mtim))
		ret.ctime.Store(dentryTimestampFromUnix(stat.Ctim))
		ret.inoKey = inoKey
	}
	return ret, nil
}

// Precondition: fs.renameMu is locked.
func (i *directfsInode) openHandle(ctx context.Context, flags uint32, d *dentry) (handle, error) {
	parent := d.parent.Load()
	if parent == nil {
		// This is a mount point. We don't have parent. Fallback to using lisafs.
		if !i.controlFDLisa.Ok() {
			panic("directfsInode.controlFDLisa is not set for mount point dentry")
		}
		openFD, hostFD, err := i.controlFDLisa.OpenAt(ctx, flags)
		if err != nil {
			return noHandle, err
		}
		i.inode.fs.client.CloseFD(ctx, openFD, true /* flush */)
		if hostFD < 0 {
			log.Warningf("gofer did not donate an FD for mount point")
			return noHandle, unix.EIO
		}
		return handle{fd: int32(hostFD)}, nil
	}

	// The only way to re-open an FD with different flags is via procfs or
	// openat(2) from the parent. Procfs does not exist here. So use parent.
	flags |= hostOpenFlags
	openFD, err := unix.Openat(parent.inode.impl.(*directfsInode).controlFD, d.name, int(flags), 0)
	if err != nil {
		return noHandle, err
	}
	return handle{fd: int32(openFD)}, nil
}

// Precondition: fs.renameMu is locked.
func (i *directfsInode) ensureLisafsControlFD(ctx context.Context, d *dentry) error {
	i.handleMu.Lock()
	defer d.inode.handleMu.Unlock()
	if d.inode.impl.(*directfsInode).controlFDLisa.Ok() {
		return nil
	}

	var names []string
	root := d
	for root.parent.Load() != nil {
		names = append(names, root.name)
		root = root.parent.Load()
	}
	if !root.inode.impl.(*directfsInode).controlFDLisa.Ok() {
		panic("controlFDLisa is not set for mount point dentry")
	}
	if len(names) == 0 {
		return nil // d == root
	}
	// Reverse names.
	last := len(names) - 1
	for i := 0; i < len(names)/2; i++ {
		names[i], names[last-i] = names[last-i], names[i]
	}
	status, inodes, err := root.inode.impl.(*directfsInode).controlFDLisa.WalkMultiple(ctx, names)
	if err != nil {
		return err
	}
	defer func() {
		// Close everything except for inodes[last] if it exists.
		for i := 0; i < len(inodes) && i < last; i++ {
			flush := i == last-1 || i == len(inodes)-1
			d.inode.fs.client.CloseFD(ctx, inodes[i].ControlFD, flush)
		}
	}()
	switch status {
	case lisafs.WalkComponentDoesNotExist:
		return unix.ENOENT
	case lisafs.WalkComponentSymlink:
		log.Warningf("intermediate path component was a symlink? names = %v, inodes = %+v", names, inodes)
		return unix.ELOOP
	case lisafs.WalkSuccess:
		d.inode.impl.(*directfsInode).controlFDLisa = d.inode.fs.client.NewFD(inodes[last].ControlFD)
		return nil
	}
	panic("unreachable")
}

// Precondition: i.inode.metadataMu must be locked.
//
// +checklocks:i.inode.metadataMu
func (i *directfsInode) updateMetadataLocked(h handle) error {
	handleMuRLocked := false
	if h.fd < 0 {
		// Use open FDs in preferenece to the control FD. Control FDs may be opened
		// with O_PATH. This may be significantly more efficient in some
		// implementations. Prefer a writable FD over a readable one since some
		// filesystem implementations may update a writable FD's metadata after
		// writes, without making metadata updates immediately visible to read-only
		// FDs representing the same file.
		i.inode.handleMu.RLock()
		switch {
		case i.inode.writeFD.RacyLoad() >= 0:
			h.fd = i.inode.writeFD.RacyLoad()
			handleMuRLocked = true
		case i.inode.readFD.RacyLoad() >= 0:
			h.fd = i.inode.readFD.RacyLoad()
			handleMuRLocked = true
		default:
			h.fd = int32(i.controlFD)
			i.inode.handleMu.RUnlock()
		}
	}

	var stat unix.Stat_t
	err := unix.Fstat(int(h.fd), &stat)
	if handleMuRLocked {
		// handleMu must be released before updateMetadataFromStatLocked().
		i.inode.handleMu.RUnlock() // +checklocksforce: complex case.
	}
	if err != nil {
		return err
	}
	return i.updateMetadataFromStatLocked(&stat)
}

// Precondition: fs.renameMu is locked if d is a socket.
func (i *directfsInode) chmod(ctx context.Context, mode uint16, d *dentry) error {
	if i.isSymlink() {
		// Linux does not support changing the mode of symlinks. See
		// fs/attr.c:notify_change().
		return unix.EOPNOTSUPP
	}
	if !i.isSocket() {
		return unix.Fchmod(i.controlFD, uint32(mode))
	}

	// Sockets use O_PATH control FDs. However, fchmod(2) fails with EBADF for
	// O_PATH FDs. Try to fchmodat(2) it from its parent.
	if parent := d.parent.Load(); parent != nil {
		return unix.Fchmodat(parent.inode.impl.(*directfsInode).controlFD, d.name, uint32(mode), 0 /* flags */)
	}

	// This is a mount point socket (no parent). Fallback to using lisafs.
	if err := i.ensureLisafsControlFD(ctx, d); err != nil {
		return err
	}
	return chmod(ctx, i.controlFDLisa, mode)
}

// Preconditions:
//   - i.inode.handleMu is locked if d is a regular file.
//   - fs.renameMu is locked if d is a symlink.
func (i *directfsInode) utimensat(ctx context.Context, stat *linux.Statx, d *dentry) error {
	if stat.Mask&(linux.STATX_ATIME|linux.STATX_MTIME) == 0 {
		return nil
	}

	utimes := [2]unix.Timespec{
		{Sec: 0, Nsec: unix.UTIME_OMIT},
		{Sec: 0, Nsec: unix.UTIME_OMIT},
	}
	if stat.Mask&unix.STATX_ATIME != 0 {
		utimes[0].Sec = stat.Atime.Sec
		utimes[0].Nsec = int64(stat.Atime.Nsec)
	}
	if stat.Mask&unix.STATX_MTIME != 0 {
		utimes[1].Sec = stat.Mtime.Sec
		utimes[1].Nsec = int64(stat.Mtime.Nsec)
	}

	if !i.isSymlink() {
		hostFD := i.controlFD
		if i.isRegularFile() {
			// utimensat(2) requires a writable FD for regular files. See BUGS
			// section. dentry.prepareSetStat() should have acquired a writable FD.
			hostFD = int(i.inode.writeFD.RacyLoad())
		}
		// Non-symlinks can operate directly on the fd using an empty name.
		return fsutil.Utimensat(hostFD, "", utimes, 0)
	}

	// utimensat operates different that other syscalls. To operate on a
	// symlink it *requires* AT_SYMLINK_NOFOLLOW with dirFD and a non-empty
	// name.
	if parent := d.parent.Load(); parent != nil {
		return fsutil.Utimensat(parent.inode.impl.(*directfsInode).controlFD, d.name, utimes, unix.AT_SYMLINK_NOFOLLOW)
	}

	// This is a mount point symlink. We don't have a parent FD. Fallback to
	// using lisafs.
	if !i.controlFDLisa.Ok() {
		panic("directfsInode.controlFDLisa is not set for mount point symlink")
	}

	setStat := linux.Statx{
		Mask:  stat.Mask & (linux.STATX_ATIME | linux.STATX_MTIME),
		Atime: stat.Atime,
		Mtime: stat.Mtime,
	}
	_, failureErr, err := i.controlFDLisa.SetStat(ctx, &setStat)
	if err != nil {
		return err
	}
	return failureErr
}

// Precondition: fs.renameMu is locked.
func (i *directfsInode) prepareSetStat(ctx context.Context, stat *linux.Statx, d *dentry) error {
	if stat.Mask&unix.STATX_SIZE != 0 ||
		(stat.Mask&(unix.STATX_ATIME|unix.STATX_MTIME) != 0 && i.isRegularFile()) {
		// Need to ensure a writable FD is available. See setStatLocked() to
		// understand why.
		return d.ensureSharedHandle(ctx, false /* read */, true /* write */, false /* trunc */)
	}
	return nil
}

// Preconditions:
//   - i.inode.handleMu is locked.
//   - fs.renameMu is locked.
func (i *directfsInode) setStatLocked(ctx context.Context, stat *linux.Statx, d *dentry) (failureMask uint32, failureErr error) {
	if stat.Mask&unix.STATX_MODE != 0 {
		if err := i.chmod(ctx, stat.Mode&^unix.S_IFMT, d); err != nil {
			failureMask |= unix.STATX_MODE
			failureErr = err
		}
	}

	if stat.Mask&unix.STATX_SIZE != 0 {
		// ftruncate(2) requires a writable FD.
		if err := unix.Ftruncate(int(i.inode.writeFD.RacyLoad()), int64(stat.Size)); err != nil {
			failureMask |= unix.STATX_SIZE
			failureErr = err
		}
	}

	if err := i.utimensat(ctx, stat, d); err != nil {
		failureMask |= (stat.Mask & (unix.STATX_ATIME | unix.STATX_MTIME))
		failureErr = err
	}

	if stat.Mask&(unix.STATX_UID|unix.STATX_GID) != 0 {
		uid := auth.KUID(auth.NoID)
		if stat.Mask&unix.STATX_UID != 0 {
			uid = auth.KUID(stat.UID)
		}
		gid := auth.KGID(auth.NoID)
		if stat.Mask&unix.STATX_GID != 0 {
			gid = auth.KGID(stat.GID)
		}
		if err := fchown(i.controlFD, uid, gid); err != nil {
			failureMask |= stat.Mask & (unix.STATX_UID | unix.STATX_GID)
			failureErr = err
		}
	}
	return
}

func fchown(fd int, uid auth.KUID, gid auth.KGID) error {
	// "If the owner or group is specified as -1, then that ID is not changed"
	// - chown(2). Only bother making the syscall if the owner is changing.
	if !uid.Ok() && !gid.Ok() {
		return nil
	}
	u := -1
	g := -1
	if uid.Ok() {
		u = int(uid)
	}
	if gid.Ok() {
		g = int(gid)
	}
	return unix.Fchownat(fd, "", u, g, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

// Precondition: i.inode.handleMu must be locked.
func (i *directfsInode) destroy(ctx context.Context) {
	if i.controlFD >= 0 {
		_ = unix.Close(i.controlFD)
		i.controlFD = -1
	}
	if i.controlFDLisa.Ok() {
		i.controlFDLisa.Close(ctx, true /* flush */)
	}
}

func (i *directfsInode) getHostChild(name string) (*dentry, error) {
	childFD, err := tryOpen(func(flags int) (int, error) {
		return unix.Openat(i.controlFD, name, flags, 0)
	})
	if err != nil {
		return nil, err
	}
	childInode, err := i.inode.fs.newDirectfsInode(childFD)
	if err != nil {
		return nil, err
	}
	return i.inode.fs.newDentry(childInode)
}

func (i *directfsInode) getXattr(ctx context.Context, name string, size uint64, d *dentry) (string, error) {
	if ftype := d.inode.fileType(); ftype == linux.S_IFSOCK || ftype == linux.S_IFLNK {
		// Sockets and symlinks use O_PATH control FDs. However, fgetxattr(2) fails
		// with EBADF for O_PATH FDs. Fallback to lisafs.
		if err := i.ensureLisafsControlFD(ctx, d); err != nil {
			return "", err
		}
		return i.controlFDLisa.GetXattr(ctx, name, size)
	}
	data := make([]byte, size)
	n, err := unix.Fgetxattr(i.controlFD, name, data)
	if err != nil {
		return "", err
	}
	return string(data[:n]), nil
}

// getCreatedChild opens the newly created child, sets its uid/gid, constructs
// a disconnected dentry and returns it.
func (i *directfsInode) getCreatedChild(name string, uid auth.KUID, gid auth.KGID, isDir bool, createDentry bool, d *dentry) (*dentry, error) {
	unlinkFlags := 0
	extraOpenFlags := 0
	if isDir {
		extraOpenFlags |= unix.O_DIRECTORY
		unlinkFlags |= unix.AT_REMOVEDIR
	}
	deleteChild := func() {
		// Best effort attempt to remove the newly created child on failure.
		if err := unix.Unlinkat(i.controlFD, name, unlinkFlags); err != nil {
			log.Warningf("error unlinking newly created child %q after failure: %v", filepath.Join(genericDebugPathname(i.inode.fs, d), name), err)
		}
	}

	childFD, err := tryOpen(func(flags int) (int, error) {
		return unix.Openat(i.controlFD, name, flags|extraOpenFlags, 0)
	})
	if err != nil {
		deleteChild()
		return nil, err
	}

	if err := fchown(childFD, uid, gid); err != nil {
		deleteChild()
		_ = unix.Close(childFD)
		return nil, err
	}

	var child *dentry
	var childInode *inode
	if createDentry {
		childInode, err = i.fs.newDirectfsInode(childFD)
		if err != nil {
			deleteChild()
			return nil, err
		}
		child, err = i.fs.newDentry(childInode)
		if err != nil {
			// Ownership of childFD was passed to newDirectDentry(), so no need to
			// clean that up.
			deleteChild()
			return nil, err
		}
	}
	return child, nil
}

func (i *directfsInode) mknod(ctx context.Context, name string, creds *auth.Credentials, opts *vfs.MknodOptions, d *dentry) (*dentry, error) {
	if _, ok := opts.Endpoint.(transport.HostBoundEndpoint); ok {
		return i.bindAt(ctx, name, creds, opts, d)
	}

	// From mknod(2) man page:
	// "EPERM: [...] if the filesystem containing pathname does not support
	// the type of node requested."
	if opts.Mode.FileType() != linux.ModeRegular {
		return nil, unix.EPERM
	}

	if err := unix.Mknodat(i.controlFD, name, uint32(opts.Mode), 0); err != nil {
		return nil, err
	}
	return i.getCreatedChild(name, creds.EffectiveKUID, creds.EffectiveKGID, false /* isDir */, true /* createDentry */, d)
}

// Precondition: opts.Endpoint != nil and is transport.HostBoundEndpoint type.
func (i *directfsInode) bindAt(ctx context.Context, name string, creds *auth.Credentials, opts *vfs.MknodOptions, d *dentry) (*dentry, error) {
	// There are no filesystems mounted in the sandbox process's mount namespace.
	// So we can't perform absolute path traversals. So fallback to using lisafs.
	if err := i.ensureLisafsControlFD(ctx, d); err != nil {
		return nil, err
	}
	sockType := opts.Endpoint.(transport.Endpoint).Type()
	childInode, boundSocketFD, err := i.controlFDLisa.BindAt(ctx, sockType, name, opts.Mode, lisafs.UID(creds.EffectiveKUID), lisafs.GID(creds.EffectiveKGID))
	if err != nil {
		return nil, err
	}
	i.inode.fs.client.CloseFD(ctx, childInode.ControlFD, true /* flush */)
	// Update opts.Endpoint that it is bound.
	hbep := opts.Endpoint.(transport.HostBoundEndpoint)
	if err := hbep.SetBoundSocketFD(ctx, boundSocketFD); err != nil {
		if err := unix.Unlinkat(i.controlFD, name, 0); err != nil {
			log.Warningf("error unlinking newly created socket %q after failure: %v", filepath.Join(genericDebugPathname(i.inode.fs, d), name), err)
		}
		return nil, err
	}
	// Socket already has the right UID/GID set, so use uid = gid = -1.
	child, err := i.getCreatedChild(name, auth.NoID /* uid */, auth.NoID /* gid */, false /* isDir */, true /* createDentry */, d)
	if err != nil {
		hbep.ResetBoundSocketFD(ctx)
		return nil, err
	}
	// Set the endpoint on the newly created child dentry, and take the
	// corresponding extra dentry reference.
	child.inode.endpoint = opts.Endpoint
	child.IncRef()
	return child, nil
}

// Precondition: i.inode.fs.renameMu must be locked.
func (i *directfsInode) link(target *dentry, name string, d *dentry) (*dentry, error) {
	// Using linkat(targetFD, "", newdirfd, name, AT_EMPTY_PATH) requires
	// CAP_DAC_READ_SEARCH in the *root* userns. With directfs, the sandbox
	// process has CAP_DAC_READ_SEARCH in its own userns. But the sandbox is
	// running in a different userns. So we can't use AT_EMPTY_PATH. Fallback to
	// using olddirfd to call linkat(2).
	// Also note that d and target are from the same mount. Given target is a
	// non-directory and d is a directory, target.parent must exist.
	if err := unix.Linkat(target.parent.Load().inode.impl.(*directfsInode).controlFD, target.name, i.controlFD, name, 0); err != nil {
		return nil, err
	}
	// Note that we don't need to set uid/gid for the new child. This is a hard
	// link. The original file already has the right owner.
	// TODO(gvisor.dev/issue/6739): Hard linked dentries should share the same
	// inode fields.
	dentry, err := i.getCreatedChild(name, auth.NoID /* uid */, auth.NoID /* gid */, false /* isDir */, true /* createDentry */, d)
	return dentry, err
}

func (i *directfsInode) mkdir(name string, mode linux.FileMode, uid auth.KUID, gid auth.KGID, createDentry bool, d *dentry) (*dentry, error) {
	if err := unix.Mkdirat(i.controlFD, name, uint32(mode)); err != nil {
		return nil, err
	}
	return i.getCreatedChild(name, uid, gid, true /* isDir */, createDentry, d)
}

func (i *directfsInode) symlink(name, target string, creds *auth.Credentials, d *dentry) (*dentry, error) {
	if err := unix.Symlinkat(target, i.controlFD, name); err != nil {
		return nil, err
	}
	return i.getCreatedChild(name, creds.EffectiveKUID, creds.EffectiveKGID, false /* isDir */, true /* createDentry */, d)
}

func (i *directfsInode) openCreate(name string, accessFlags uint32, mode linux.FileMode, uid auth.KUID, gid auth.KGID, createDentry bool, d *dentry) (*dentry, handle, error) {
	createFlags := unix.O_CREAT | unix.O_EXCL | int(accessFlags) | hostOpenFlags
	childHandleFD, err := unix.Openat(i.controlFD, name, createFlags, uint32(mode&^linux.FileTypeMask))
	if err != nil {
		return nil, noHandle, err
	}

	child, err := i.getCreatedChild(name, uid, gid, false /* isDir */, createDentry, d)
	if err != nil {
		_ = unix.Close(childHandleFD)
		return nil, noHandle, err
	}
	return child, handle{fd: int32(childHandleFD)}, nil
}

func (i *directfsInode) getDirentsLocked(recordDirent func(name string, key inoKey, dType uint8), d *dentry) error {
	readFD := int(i.inode.readFD.RacyLoad())
	if _, err := unix.Seek(readFD, 0, 0); err != nil {
		return err
	}

	return fsutil.ForEachDirent(readFD, func(ino uint64, off int64, ftype uint8, name string, reclen uint16) {
		// We also want the device ID, which annoyingly incurs an additional
		// syscall per dirent.
		// TODO(gvisor.dev/issue/6665): Get rid of per-dirent stat.
		stat, err := fsutil.StatAt(i.controlFD, name)
		if err != nil {
			log.Warningf("Getdent64: skipping file %q with failed stat, err: %v", path.Join(genericDebugPathname(i.inode.fs, d), name), err)
			return
		}
		recordDirent(name, inoKeyFromStat(&stat), ftype)
	})
}

// Precondition: fs.renameMu is locked.
func (i *directfsInode) connect(ctx context.Context, sockType linux.SockType, euid lisafs.UID, egid lisafs.GID, d *dentry) (int, error) {
	// There are no filesystems mounted in the sandbox process's mount namespace.
	// So we can't perform absolute path traversals. So fallback to using lisafs.
	if err := i.ensureLisafsControlFD(ctx, d); err != nil {
		return -1, err
	}
	return i.controlFDLisa.Connect(ctx, sockType, euid, egid)
}

func (i *directfsInode) readlink() (string, error) {
	// This is similar to what os.Readlink does.
	for linkLen := 128; linkLen < math.MaxUint16; linkLen *= 2 {
		b := make([]byte, linkLen)
		n, err := unix.Readlinkat(i.controlFD, "", b)

		if err != nil {
			return "", err
		}
		if n < int(linkLen) {
			return string(b[:n]), nil
		}
	}
	return "", unix.ENOMEM
}

func (i *directfsInode) statfs() (linux.Statfs, error) {
	var statFS unix.Statfs_t
	if err := unix.Fstatfs(i.controlFD, &statFS); err != nil {
		return linux.Statfs{}, err
	}
	return linux.Statfs{
		BlockSize:       statFS.Bsize,
		FragmentSize:    statFS.Bsize,
		Blocks:          statFS.Blocks,
		BlocksFree:      statFS.Bfree,
		BlocksAvailable: statFS.Bavail,
		Files:           statFS.Files,
		FilesFree:       statFS.Ffree,
		NameLength:      uint64(statFS.Namelen),
	}, nil
}

func (i *directfsInode) restoreFile(ctx context.Context, controlFD int, opts *vfs.CompleteRestoreOptions, d *dentry) error {
	if controlFD < 0 {
		return fmt.Errorf("directfsInode.restoreFile called with invalid controlFD")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(controlFD, &stat); err != nil {
		_ = unix.Close(controlFD)
		return fmt.Errorf("failed to stat %q: %w", genericDebugPathname(i.inode.fs, d), err)
	}
	i.controlFD = controlFD
	// We do not preserve inoKey across checkpoint/restore, so:
	//
	//	- We must assume that the host filesystem did not change in a way that
	//		would invalidate dentries, since we can't revalidate dentries by
	//		checking inoKey.
	//
	//	- We need to associate the new inoKey with the existing d.ino.
	i.inoKey = inoKeyFromStat(&stat)
	i.fs.inoMu.Lock()
	i.fs.inoByKey[i.inode.inoKey] = i.ino
	i.fs.inoMu.Unlock()
	i.fs.inodeByInoMu.Lock()
	i.fs.inodeByIno[i.inoKey] = &i.inode
	i.fs.inodeByInoMu.Unlock()

	// Check metadata stability before updating metadata.
	i.inode.metadataMu.Lock()
	defer i.inode.metadataMu.Unlock()
	if i.isRegularFile() {
		if opts.ValidateFileSizes {
			if i.inode.size.RacyLoad() != uint64(stat.Size) {
				return vfs.ErrCorruption{Err: fmt.Errorf("gofer.dentry(%q).restoreFile: file size validation failed: size changed from %d to %d", genericDebugPathname(i.inode.fs, d), i.inode.size.Load(), stat.Size)}
			}
		}
		if opts.ValidateFileModificationTimestamps {
			if want := dentryTimestampFromUnix(stat.Mtim); i.inode.mtime.RacyLoad() != want {
				return vfs.ErrCorruption{Err: fmt.Errorf("gofer.dentry(%q).restoreFile: mtime validation failed: mtime changed from %+v to %+v", genericDebugPathname(i.inode.fs, d), linux.NsecToStatxTimestamp(i.inode.mtime.RacyLoad()), linux.NsecToStatxTimestamp(want))}
			}
		}
	}
	if !i.cachedMetadataAuthoritative() {
		i.updateMetadataFromStatLocked(&stat)
	}

	if rw, ok := i.inode.fs.savedDentryRW[d]; ok {
		if err := d.ensureSharedHandle(ctx, rw.read, rw.write, false /* trunc */); err != nil {
			return fmt.Errorf("failed to restore file handles (read=%t, write=%t) for %q: %w", rw.read, rw.write, genericDebugPathname(i.inode.fs, d), err)
		}
	}

	return nil
}

// doRevalidationDirectfs stats all dentries in `state`. It will update or
// invalidate dentries in the cache based on the result.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - InteropModeShared is in effect.
func doRevalidationDirectfs(ctx context.Context, vfsObj *vfs.VirtualFilesystem, state *revalidateState, ds **[]*dentry) error {
	// Explicitly declare start dentry, instead of using the function receiver.
	// The function receiver has to be named `d` (to be consistent with other
	// receivers). But `d` variable is also used below in various places. This
	// helps with readability and makes code less error prone.
	start := state.start.inode.impl.(*directfsInode)
	if state.refreshStart {
		start.updateMetadata(ctx)
	}

	parent := start
	for _, d := range state.dentries {
		childFD, err := unix.Openat(parent.controlFD, d.name, unix.O_PATH|hostOpenFlags, 0)
		if err != nil && err != unix.ENOENT {
			return err
		}

		var stat unix.Stat_t
		// Lock metadata *before* getting attributes for d.
		d.inode.metadataMu.Lock()
		found := err == nil
		if found {
			err = unix.Fstat(childFD, &stat)
			_ = unix.Close(childFD)
			if err != nil {
				d.inode.metadataMu.Unlock()
				return err
			}
		}

		// Note that synthetic dentries will always fail this comparison check.
		if !found || d.inode.inoKey != inoKeyFromStat(&stat) {
			d.inode.metadataMu.Unlock()
			if !found && d.inode.isSynthetic() {
				// We have a synthetic file, and no remote file has arisen to replace
				// it.
				return nil
			}
			// The file at this path has changed or no longer exists. Mark the
			// dentry invalidated.
			d.invalidate(ctx, vfsObj, ds)
			return nil
		}

		// The file at this path hasn't changed. Just update cached metadata.
		d.inode.impl.(*directfsInode).updateMetadataFromStatLocked(&stat) // +checklocksforce: i.inode.metadataMu is locked above.
		d.inode.metadataMu.Unlock()

		// Advance parent.
		parent = d.inode.impl.(*directfsInode)
	}
	return nil
}

// LINT.ThenChange(../../../../runsc/fsgofer/lisafs.go)
