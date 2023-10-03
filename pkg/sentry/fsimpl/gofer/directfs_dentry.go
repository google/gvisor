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
	"gvisor.dev/gvisor/pkg/atomicbitops"
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

// getDirectfsRootDentry creates a new dentry representing the root dentry for
// this mountpoint. getDirectfsRootDentry takes ownership of rootHostFD and
// rootControlFD.
func (fs *filesystem) getDirectfsRootDentry(ctx context.Context, rootHostFD int, rootControlFD lisafs.ClientFD) (*dentry, error) {
	d, err := fs.newDirectfsDentry(rootHostFD)
	if err != nil {
		log.Warningf("newDirectfsDentry failed for mount point dentry: %v", err)
		rootControlFD.Close(ctx, false /* flush */)
		return nil, err
	}
	d.impl.(*directfsDentry).controlFDLisa = rootControlFD
	return d, nil
}

// directfsDentry is a host dentry implementation. It represents a dentry
// backed by a host file descriptor. All operations are directly performed on
// the host. A gofer is only involved for some operations on the mount point
// dentry (when dentry.parent = nil). We are forced to fall back to the gofer
// due to the lack of procfs in the sandbox process.
//
// +stateify savable
type directfsDentry struct {
	dentry

	// controlFD is the host FD to this file. controlFD is immutable.
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

// newDirectfsDentry creates a new dentry representing the given file. The dentry
// initially has no references, but is not cached; it is the caller's
// responsibility to set the dentry's reference count and/or call
// dentry.checkCachingLocked() as appropriate.
// newDirectDentry takes ownership of controlFD.
func (fs *filesystem) newDirectfsDentry(controlFD int) (*dentry, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(controlFD, &stat); err != nil {
		log.Warningf("failed to fstat(2) FD %d: %v", controlFD, err)
		_ = unix.Close(controlFD)
		return nil, err
	}
	inoKey := inoKeyFromStat(&stat)
	d := &directfsDentry{
		dentry: dentry{
			fs:        fs,
			inoKey:    inoKey,
			ino:       fs.inoFromKey(inoKey),
			mode:      atomicbitops.FromUint32(stat.Mode),
			uid:       atomicbitops.FromUint32(stat.Uid),
			gid:       atomicbitops.FromUint32(stat.Gid),
			blockSize: atomicbitops.FromUint32(uint32(stat.Blksize)),
			readFD:    atomicbitops.FromInt32(-1),
			writeFD:   atomicbitops.FromInt32(-1),
			mmapFD:    atomicbitops.FromInt32(-1),
			size:      atomicbitops.FromUint64(uint64(stat.Size)),
			atime:     atomicbitops.FromInt64(dentryTimestampFromUnix(stat.Atim)),
			mtime:     atomicbitops.FromInt64(dentryTimestampFromUnix(stat.Mtim)),
			ctime:     atomicbitops.FromInt64(dentryTimestampFromUnix(stat.Ctim)),
			nlink:     atomicbitops.FromUint32(uint32(stat.Nlink)),
		},
		controlFD: controlFD,
	}
	d.dentry.init(d)
	fs.syncMu.Lock()
	fs.syncableDentries.PushBack(&d.syncableListEntry)
	fs.syncMu.Unlock()
	return &d.dentry, nil
}

// Precondition: fs.renameMu is locked.
func (d *directfsDentry) openHandle(ctx context.Context, flags uint32) (handle, error) {
	parent := d.parent.Load()
	if parent == nil {
		// This is a mount point. We don't have parent. Fallback to using lisafs.
		if !d.controlFDLisa.Ok() {
			panic("directfsDentry.controlFDLisa is not set for mount point dentry")
		}
		openFD, hostFD, err := d.controlFDLisa.OpenAt(ctx, flags)
		if err != nil {
			return noHandle, err
		}
		d.fs.client.CloseFD(ctx, openFD, true /* flush */)
		if hostFD < 0 {
			log.Warningf("gofer did not donate an FD for mount point")
			return noHandle, unix.EIO
		}
		return handle{fd: int32(hostFD)}, nil
	}

	// The only way to re-open an FD with different flags is via procfs or
	// openat(2) from the parent. Procfs does not exist here. So use parent.
	flags |= hostOpenFlags
	openFD, err := unix.Openat(parent.impl.(*directfsDentry).controlFD, d.name, int(flags), 0)
	if err != nil {
		return noHandle, err
	}
	return handle{fd: int32(openFD)}, nil
}

// Precondition: fs.renameMu is locked.
func (d *directfsDentry) ensureLisafsControlFD(ctx context.Context) error {
	d.handleMu.Lock()
	defer d.handleMu.Unlock()
	if d.controlFDLisa.Ok() {
		return nil
	}

	var names []string
	root := d
	for root.parent.Load() != nil {
		names = append(names, root.name)
		root = root.parent.Load().impl.(*directfsDentry)
	}
	if !root.controlFDLisa.Ok() {
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
	status, inodes, err := root.controlFDLisa.WalkMultiple(ctx, names)
	if err != nil {
		return err
	}
	defer func() {
		// Close everything except for inodes[last] if it exists.
		for i := 0; i < len(inodes) && i < last; i++ {
			flush := i == last-1 || i == len(inodes)-1
			d.fs.client.CloseFD(ctx, inodes[i].ControlFD, flush)
		}
	}()
	switch status {
	case lisafs.WalkComponentDoesNotExist:
		return unix.ENOENT
	case lisafs.WalkComponentSymlink:
		log.Warningf("intermediate path component was a symlink? names = %v, inodes = %+v", names, inodes)
		return unix.ELOOP
	case lisafs.WalkSuccess:
		d.controlFDLisa = d.fs.client.NewFD(inodes[last].ControlFD)
		return nil
	}
	panic("unreachable")
}

// Precondition: d.metadataMu must be locked.
//
// +checklocks:d.metadataMu
func (d *directfsDentry) updateMetadataLocked(h handle) error {
	handleMuRLocked := false
	if h.fd < 0 {
		// Use open FDs in preferenece to the control FD. Control FDs may be opened
		// with O_PATH. This may be significantly more efficient in some
		// implementations. Prefer a writable FD over a readable one since some
		// filesystem implementations may update a writable FD's metadata after
		// writes, without making metadata updates immediately visible to read-only
		// FDs representing the same file.
		d.handleMu.RLock()
		switch {
		case d.writeFD.RacyLoad() >= 0:
			h.fd = d.writeFD.RacyLoad()
			handleMuRLocked = true
		case d.readFD.RacyLoad() >= 0:
			h.fd = d.readFD.RacyLoad()
			handleMuRLocked = true
		default:
			h.fd = int32(d.controlFD)
			d.handleMu.RUnlock()
		}
	}

	var stat unix.Stat_t
	err := unix.Fstat(int(h.fd), &stat)
	if handleMuRLocked {
		// handleMu must be released before updateMetadataFromStatLocked().
		d.handleMu.RUnlock() // +checklocksforce: complex case.
	}
	if err != nil {
		return err
	}
	return d.updateMetadataFromStatLocked(&stat)
}

// Precondition: fs.renameMu is locked if d is a socket.
func (d *directfsDentry) chmod(ctx context.Context, mode uint16) error {
	if !d.isSocket() {
		return unix.Fchmod(d.controlFD, uint32(mode))
	}

	// fchmod(2) on socket files created via bind(2) fails. We need to
	// fchmodat(2) it from its parent.
	if parent := d.parent.Load(); parent != nil {
		// We have parent FD, just use that. Note that AT_SYMLINK_NOFOLLOW flag is
		// currently not supported. So we don't use it.
		return unix.Fchmodat(parent.impl.(*directfsDentry).controlFD, d.name, uint32(mode), 0 /* flags */)
	}

	// This is a mount point socket. We don't have a parent FD. Fallback to using
	// lisafs.
	if !d.controlFDLisa.Ok() {
		panic("directfsDentry.controlFDLisa is not set for mount point socket")
	}

	return chmod(ctx, d.controlFDLisa, mode)
}

// Preconditions:
//   - d.handleMu is locked if d is a regular file.
//   - fs.renameMu is locked if d is a symlink.
func (d *directfsDentry) utimensat(ctx context.Context, stat *linux.Statx) error {
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

	if !d.isSymlink() {
		hostFD := d.controlFD
		if d.isRegularFile() {
			// utimensat(2) requires a writable FD for regular files. See BUGS
			// section. dentry.prepareSetStat() should have acquired a writable FD.
			hostFD = int(d.writeFD.RacyLoad())
		}
		// Non-symlinks can operate directly on the fd using an empty name.
		return fsutil.Utimensat(hostFD, "", utimes, 0)
	}

	// utimensat operates different that other syscalls. To operate on a
	// symlink it *requires* AT_SYMLINK_NOFOLLOW with dirFD and a non-empty
	// name.
	if parent := d.parent.Load(); parent != nil {
		return fsutil.Utimensat(parent.impl.(*directfsDentry).controlFD, d.name, utimes, unix.AT_SYMLINK_NOFOLLOW)
	}

	// This is a mount point symlink. We don't have a parent FD. Fallback to
	// using lisafs.
	if !d.controlFDLisa.Ok() {
		panic("directfsDentry.controlFDLisa is not set for mount point symlink")
	}

	setStat := linux.Statx{
		Mask:  stat.Mask & (linux.STATX_ATIME | linux.STATX_MTIME),
		Atime: stat.Atime,
		Mtime: stat.Mtime,
	}
	_, failureErr, err := d.controlFDLisa.SetStat(ctx, &setStat)
	if err != nil {
		return err
	}
	return failureErr
}

// Precondition: fs.renameMu is locked.
func (d *directfsDentry) prepareSetStat(ctx context.Context, stat *linux.Statx) error {
	if stat.Mask&unix.STATX_SIZE != 0 ||
		(stat.Mask&(unix.STATX_ATIME|unix.STATX_MTIME) != 0 && d.isRegularFile()) {
		// Need to ensure a writable FD is available. See setStatLocked() to
		// understand why.
		return d.ensureSharedHandle(ctx, false /* read */, true /* write */, false /* trunc */)
	}
	return nil
}

// Preconditions:
//   - d.handleMu is locked.
//   - fs.renameMu is locked.
func (d *directfsDentry) setStatLocked(ctx context.Context, stat *linux.Statx) (failureMask uint32, failureErr error) {
	if stat.Mask&unix.STATX_MODE != 0 {
		if err := d.chmod(ctx, stat.Mode&^unix.S_IFMT); err != nil {
			failureMask |= unix.STATX_MODE
			failureErr = err
		}
	}

	if stat.Mask&unix.STATX_SIZE != 0 {
		// ftruncate(2) requires a writable FD.
		if err := unix.Ftruncate(int(d.writeFD.RacyLoad()), int64(stat.Size)); err != nil {
			failureMask |= unix.STATX_SIZE
			failureErr = err
		}
	}

	if err := d.utimensat(ctx, stat); err != nil {
		failureMask |= (stat.Mask & (unix.STATX_ATIME | unix.STATX_MTIME))
		failureErr = err
	}

	if stat.Mask&(unix.STATX_UID|unix.STATX_GID) != 0 {
		// "If the owner or group is specified as -1, then that ID is not changed"
		// - chown(2)
		uid := -1
		if stat.Mask&unix.STATX_UID != 0 {
			uid = int(stat.UID)
		}
		gid := -1
		if stat.Mask&unix.STATX_GID != 0 {
			gid = int(stat.GID)
		}
		if err := fchown(d.controlFD, uid, gid); err != nil {
			failureMask |= stat.Mask & (unix.STATX_UID | unix.STATX_GID)
			failureErr = err
		}
	}
	return
}

func fchown(fd, uid, gid int) error {
	return unix.Fchownat(fd, "", uid, gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

func (d *directfsDentry) destroy(ctx context.Context) {
	if d.controlFD >= 0 {
		_ = unix.Close(d.controlFD)
	}
	if d.controlFDLisa.Ok() {
		d.controlFDLisa.Close(ctx, true /* flush */)
	}
}

func (d *directfsDentry) getHostChild(name string) (*dentry, error) {
	childFD, err := tryOpen(func(flags int) (int, error) {
		return unix.Openat(d.controlFD, name, flags, 0)
	})
	if err != nil {
		return nil, err
	}
	return d.fs.newDirectfsDentry(childFD)
}

// getCreatedChild opens the newly created child, sets its uid/gid, constructs
// a disconnected dentry and returns it.
func (d *directfsDentry) getCreatedChild(name string, uid, gid int, isDir bool) (*dentry, error) {
	unlinkFlags := 0
	extraOpenFlags := 0
	if isDir {
		extraOpenFlags |= unix.O_DIRECTORY
		unlinkFlags |= unix.AT_REMOVEDIR
	}
	deleteChild := func() {
		// Best effort attempt to remove the newly created child on failure.
		if err := unix.Unlinkat(d.controlFD, name, unlinkFlags); err != nil {
			log.Warningf("error unlinking newly created child %q after failure: %v", filepath.Join(genericDebugPathname(&d.dentry), name), err)
		}
	}

	childFD, err := tryOpen(func(flags int) (int, error) {
		return unix.Openat(d.controlFD, name, flags|extraOpenFlags, 0)
	})
	if err != nil {
		deleteChild()
		return nil, err
	}

	// "If the owner or group is specified as -1, then that ID is not changed"
	// - chown(2). Only bother making the syscall if the owner is changing.
	if uid != -1 || gid != -1 {
		if err := fchown(childFD, uid, gid); err != nil {
			deleteChild()
			_ = unix.Close(childFD)
			return nil, err
		}
	}
	child, err := d.fs.newDirectfsDentry(childFD)
	if err != nil {
		// Ownership of childFD was passed to newDirectDentry(), so no need to
		// clean that up.
		deleteChild()
		return nil, err
	}
	return child, nil
}

func (d *directfsDentry) mknod(ctx context.Context, name string, creds *auth.Credentials, opts *vfs.MknodOptions) (*dentry, error) {
	if _, ok := opts.Endpoint.(transport.HostBoundEndpoint); ok {
		return d.bindAt(ctx, name, creds, opts)
	}

	// From mknod(2) man page:
	// "EPERM: [...] if the filesystem containing pathname does not support
	// the type of node requested."
	if opts.Mode.FileType() != linux.ModeRegular {
		return nil, unix.EPERM
	}

	if err := unix.Mknodat(d.controlFD, name, uint32(opts.Mode), 0); err != nil {
		return nil, err
	}
	return d.getCreatedChild(name, int(creds.EffectiveKUID), int(creds.EffectiveKGID), false /* isDir */)
}

// Precondition: opts.Endpoint != nil and is transport.HostBoundEndpoint type.
func (d *directfsDentry) bindAt(ctx context.Context, name string, creds *auth.Credentials, opts *vfs.MknodOptions) (*dentry, error) {
	// There are no filesystems mounted in the sandbox process's mount namespace.
	// So we can't perform absolute path traversals. So fallback to using lisafs.
	if err := d.ensureLisafsControlFD(ctx); err != nil {
		return nil, err
	}
	sockType := opts.Endpoint.(transport.Endpoint).Type()
	childInode, boundSocketFD, err := d.controlFDLisa.BindAt(ctx, sockType, name, opts.Mode, lisafs.UID(creds.EffectiveKUID), lisafs.GID(creds.EffectiveKGID))
	if err != nil {
		return nil, err
	}
	d.fs.client.CloseFD(ctx, childInode.ControlFD, true /* flush */)
	// Update opts.Endpoint that it is bound.
	hbep := opts.Endpoint.(transport.HostBoundEndpoint)
	if err := hbep.SetBoundSocketFD(ctx, boundSocketFD); err != nil {
		if err := unix.Unlinkat(d.controlFD, name, 0); err != nil {
			log.Warningf("error unlinking newly created socket %q after failure: %v", filepath.Join(genericDebugPathname(&d.dentry), name), err)
		}
		return nil, err
	}
	// Socket already has the right UID/GID set, so use uid = gid = -1.
	child, err := d.getCreatedChild(name, -1 /* uid */, -1 /* gid */, false /* isDir */)
	if err != nil {
		hbep.ResetBoundSocketFD(ctx)
		return nil, err
	}
	// Set the endpoint on the newly created child dentry.
	child.endpoint = opts.Endpoint
	return child, nil
}

// Precondition: d.fs.renameMu must be locked.
func (d *directfsDentry) link(target *directfsDentry, name string) (*dentry, error) {
	// Using linkat(targetFD, "", newdirfd, name, AT_EMPTY_PATH) requires
	// CAP_DAC_READ_SEARCH in the *root* userns. With directfs, the sandbox
	// process has CAP_DAC_READ_SEARCH in its own userns. But the sandbox is
	// running in a different userns. So we can't use AT_EMPTY_PATH. Fallback to
	// using olddirfd to call linkat(2).
	// Also note that d and target are from the same mount. Given target is a
	// non-directory and d is a directory, target.parent must exist.
	if err := unix.Linkat(target.parent.Load().impl.(*directfsDentry).controlFD, target.name, d.controlFD, name, 0); err != nil {
		return nil, err
	}
	// Note that we don't need to set uid/gid for the new child. This is a hard
	// link. The original file already has the right owner.
	return d.getCreatedChild(name, -1 /* uid */, -1 /* gid */, false /* isDir */)
}

func (d *directfsDentry) mkdir(name string, mode linux.FileMode, uid auth.KUID, gid auth.KGID) (*dentry, error) {
	if err := unix.Mkdirat(d.controlFD, name, uint32(mode)); err != nil {
		return nil, err
	}
	return d.getCreatedChild(name, int(uid), int(gid), true /* isDir */)
}

func (d *directfsDentry) symlink(name, target string, creds *auth.Credentials) (*dentry, error) {
	if err := unix.Symlinkat(target, d.controlFD, name); err != nil {
		return nil, err
	}
	return d.getCreatedChild(name, int(creds.EffectiveKUID), int(creds.EffectiveKGID), false /* isDir */)
}

func (d *directfsDentry) openCreate(name string, accessFlags uint32, mode linux.FileMode, uid auth.KUID, gid auth.KGID) (*dentry, handle, error) {
	createFlags := unix.O_CREAT | unix.O_EXCL | int(accessFlags) | hostOpenFlags
	childHandleFD, err := unix.Openat(d.controlFD, name, createFlags, uint32(mode&^linux.FileTypeMask))
	if err != nil {
		return nil, noHandle, err
	}

	child, err := d.getCreatedChild(name, int(uid), int(gid), false /* isDir */)
	if err != nil {
		_ = unix.Close(childHandleFD)
		return nil, noHandle, err
	}
	return child, handle{fd: int32(childHandleFD)}, nil
}

func (d *directfsDentry) getDirentsLocked(recordDirent func(name string, key inoKey, dType uint8)) error {
	readFD := int(d.readFD.RacyLoad())
	if _, err := unix.Seek(readFD, 0, 0); err != nil {
		return err
	}

	var direntsBuf [8192]byte
	for {
		n, err := unix.Getdents(readFD, direntsBuf[:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return nil
		}

		fsutil.ParseDirents(direntsBuf[:n], func(ino uint64, off int64, ftype uint8, name string, reclen uint16) bool {
			// We also want the device ID, which annoyingly incurs an additional
			// syscall per dirent.
			// TODO(gvisor.dev/issue/6665): Get rid of per-dirent stat.
			stat, err := fsutil.StatAt(d.controlFD, name)
			if err != nil {
				log.Warningf("Getdent64: skipping file %q with failed stat, err: %v", path.Join(genericDebugPathname(&d.dentry), name), err)
				return true
			}
			recordDirent(name, inoKeyFromStat(&stat), ftype)
			return true
		})
	}
}

// Precondition: fs.renameMu is locked.
func (d *directfsDentry) connect(ctx context.Context, sockType linux.SockType) (int, error) {
	// There are no filesystems mounted in the sandbox process's mount namespace.
	// So we can't perform absolute path traversals. So fallback to using lisafs.
	if err := d.ensureLisafsControlFD(ctx); err != nil {
		return -1, err
	}
	return d.controlFDLisa.Connect(ctx, sockType)
}

func (d *directfsDentry) readlink() (string, error) {
	// This is similar to what os.Readlink does.
	for linkLen := 128; linkLen < math.MaxUint16; linkLen *= 2 {
		b := make([]byte, linkLen)
		n, err := unix.Readlinkat(d.controlFD, "", b)

		if err != nil {
			return "", err
		}
		if n < int(linkLen) {
			return string(b[:n]), nil
		}
	}
	return "", unix.ENOMEM
}

func (d *directfsDentry) statfs() (linux.Statfs, error) {
	var statFS unix.Statfs_t
	if err := unix.Fstatfs(d.controlFD, &statFS); err != nil {
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

func (d *directfsDentry) restoreFile(ctx context.Context, controlFD int, opts *vfs.CompleteRestoreOptions) error {
	if controlFD < 0 {
		log.Warningf("directfsDentry.restoreFile called with invalid controlFD")
		return unix.EINVAL
	}
	var stat unix.Stat_t
	if err := unix.Fstat(controlFD, &stat); err != nil {
		_ = unix.Close(controlFD)
		return err
	}

	d.controlFD = controlFD
	// We do not preserve inoKey across checkpoint/restore, so:
	//
	//	- We must assume that the host filesystem did not change in a way that
	//		would invalidate dentries, since we can't revalidate dentries by
	//		checking inoKey.
	//
	//	- We need to associate the new inoKey with the existing d.ino.
	d.inoKey = inoKeyFromStat(&stat)
	d.fs.inoMu.Lock()
	d.fs.inoByKey[d.inoKey] = d.ino
	d.fs.inoMu.Unlock()

	// Check metadata stability before updating metadata.
	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()
	if d.isRegularFile() {
		if opts.ValidateFileSizes {
			if d.size.RacyLoad() != uint64(stat.Size) {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: file size validation failed: size changed from %d to %d", genericDebugPathname(&d.dentry), d.size.Load(), stat.Size)}
			}
		}
		if opts.ValidateFileModificationTimestamps {
			if want := dentryTimestampFromUnix(stat.Mtim); d.mtime.RacyLoad() != want {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: mtime validation failed: mtime changed from %+v to %+v", genericDebugPathname(&d.dentry), linux.NsecToStatxTimestamp(d.mtime.RacyLoad()), linux.NsecToStatxTimestamp(want))}
			}
		}
	}
	if !d.cachedMetadataAuthoritative() {
		d.updateMetadataFromStatLocked(&stat)
	}

	if rw, ok := d.fs.savedDentryRW[&d.dentry]; ok {
		if err := d.ensureSharedHandle(ctx, rw.read, rw.write, false /* trunc */); err != nil {
			return err
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
	start := state.start.impl.(*directfsDentry)
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
		d.metadataMu.Lock()
		found := err == nil
		if found {
			err = unix.Fstat(childFD, &stat)
			_ = unix.Close(childFD)
			if err != nil {
				d.metadataMu.Unlock()
				return err
			}
		}

		// Note that synthetic dentries will always fail this comparison check.
		if !found || d.inoKey != inoKeyFromStat(&stat) {
			d.metadataMu.Unlock()
			if !found && d.isSynthetic() {
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
		d.impl.(*directfsDentry).updateMetadataFromStatLocked(&stat) // +checklocksforce: d.metadataMu is locked above.
		d.metadataMu.Unlock()

		// Advance parent.
		parent = d.impl.(*directfsDentry)
	}
	return nil
}

// LINT.ThenChange(../../../../runsc/fsgofer/lisafs.go)
