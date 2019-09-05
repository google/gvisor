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

// Package fsgofer implements p9.File giving access to local files using
// a simple mapping from a path prefix that is added to the path requested
// by the sandbox. Ex:
//
//   prefix: "/docker/imgs/alpine"
//   app path: /bin/ls => /docker/imgs/alpine/bin/ls
package fsgofer

import (
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	// invalidMode is set to a value that doesn't match any other valid
	// modes to ensure an unopened/closed file fails all mode checks.
	invalidMode = p9.OpenFlags(math.MaxUint32)

	openFlags = syscall.O_NOFOLLOW | syscall.O_CLOEXEC
)

type fileType int

const (
	regular fileType = iota
	directory
	symlink
	socket
	unknown
)

// String implements fmt.Stringer.
func (f fileType) String() string {
	switch f {
	case regular:
		return "regular"
	case directory:
		return "directory"
	case symlink:
		return "symlink"
	case socket:
		return "socket"
	}
	return "unknown"
}

// ControlSocketAddr generates an abstract unix socket name for the given id.
func ControlSocketAddr(id string) string {
	return fmt.Sprintf("\x00runsc-gofer.%s", id)
}

// Config sets configuration options for each attach point.
type Config struct {
	// ROMount is set to true if this is a readonly mount.
	ROMount bool

	// PanicOnWrite panics on attempts to write to RO mounts.
	PanicOnWrite bool
}

type attachPoint struct {
	prefix string
	conf   Config

	// attachedMu protects attached.
	attachedMu sync.Mutex
	attached   bool

	// deviceMu protects devices and nextDevice.
	deviceMu sync.Mutex

	// nextDevice is the next device id that will be allocated.
	nextDevice uint8

	// devices is a map from actual host devices to "small" integers that
	// can be combined with host inode to form a unique virtual inode id.
	devices map[uint64]uint8
}

// NewAttachPoint creates a new attacher that gives local file
// access to all files under 'prefix'. 'prefix' must be an absolute path.
func NewAttachPoint(prefix string, c Config) (p9.Attacher, error) {
	// Sanity check the prefix.
	if !filepath.IsAbs(prefix) {
		return nil, fmt.Errorf("attach point prefix must be absolute %q", prefix)
	}
	return &attachPoint{
		prefix:  prefix,
		conf:    c,
		devices: make(map[uint64]uint8),
	}, nil
}

// Attach implements p9.Attacher.
func (a *attachPoint) Attach() (p9.File, error) {
	// dirFD (1st argument) is ignored because 'prefix' is always absolute.
	stat, err := statAt(-1, a.prefix)
	if err != nil {
		return nil, fmt.Errorf("stat file %q, err: %v", a.prefix, err)
	}

	// Hold the file descriptor we are converting into a p9.File
	var f *fd.FD

  // Apply the S_IFMT bitmask so we can detect file type appropriately
	switch fmtStat := stat.Mode & syscall.S_IFMT; {
	case fmtStat == syscall.S_IFSOCK:
			// Attempt to open a connection. Bubble up the failures.
			f, err = fd.OpenUnix(a.prefix)
			if err != nil {
				return nil, err
			}

		default:
			// Default to Read/Write permissions.
			mode := syscall.O_RDWR

			// If the configuration is Read Only & the mount point is a directory,
			// set the mode to Read Only.
			if a.conf.ROMount || fmtStat == syscall.S_IFDIR {
				mode = syscall.O_RDONLY
			}

			// Open the mount point & capture the FD.
			f, err = fd.Open(a.prefix, openFlags|mode, 0)
			if err != nil {
				return nil, fmt.Errorf("unable to open file %q, err: %v", a.prefix, err)
			}
	}

	// Close the connection if the UDS is already attached.
	a.attachedMu.Lock()
	defer a.attachedMu.Unlock()
	if a.attached {
		f.Close()
		return nil, fmt.Errorf("attach point already attached, prefix: %s", a.prefix)
	}
	a.attached = true

	// Return a localFile object to the caller with the UDS FD included.
	return newLocalFile(a, f, a.prefix, stat)
}

// makeQID returns a unique QID for the given stat buffer.
func (a *attachPoint) makeQID(stat syscall.Stat_t) p9.QID {
	a.deviceMu.Lock()
	defer a.deviceMu.Unlock()

	// First map the host device id to a unique 8-bit integer.
	dev, ok := a.devices[stat.Dev]
	if !ok {
		a.devices[stat.Dev] = a.nextDevice
		dev = a.nextDevice
		a.nextDevice++
		if a.nextDevice < dev {
			panic(fmt.Sprintf("device id overflow! map: %+v", a.devices))
		}
	}

	// Construct a "virtual" inode id with the uint8 device number in the
	// first 8 bits, and the rest of the bits from the host inode id.
	maskedIno := stat.Ino & 0x00ffffffffffffff
	if maskedIno != stat.Ino {
		log.Warningf("first 8 bytes of host inode id %x will be truncated to construct virtual inode id", stat.Ino)
	}
	ino := uint64(dev)<<56 | maskedIno
	log.Debugf("host inode %x on device %x mapped to virtual inode %x", stat.Ino, stat.Dev, ino)

	return p9.QID{
		Type: p9.FileMode(stat.Mode).QIDType(),
		Path: ino,
	}
}

// localFile implements p9.File wrapping a local file. The underlying file
// is opened during Walk() and stored in 'file' to be used with other
// operations. The file is opened as readonly, unless it's a symlink or there is
// no read access, which requires O_PATH. 'file' is dup'ed when Walk(nil) is
// called to clone the file. This reduces the number of walks that need to be
// done by the host file system when files are reused.
//
// The file may be reopened if the requested mode in Open() is not a subset of
// current mode. Consequently, 'file' could have a mode wider than requested and
// must be verified before read/write operations. Before the file is opened and
// after it's closed, 'mode' is set to an invalid value to prevent an unopened
// file from being used.
//
// The reason that the file is not opened initially as read-write is for better
// performance with 'overlay2' storage driver. overlay2 eagerly copies the
// entire file up when it's opened in write mode, and would perform badly when
type localFile struct {
	p9.DefaultWalkGetAttr

	// attachPoint is the attachPoint that serves this localFile.
	attachPoint *attachPoint

	// hostPath will be safely updated by the Renamed hook.
	hostPath string

	// file is opened when localFile is created and it's never nil. It may be
	// reopened if the Open() mode is wider than the mode the file was originally
	// opened with.
	file *fd.FD

	// mode is the mode in which the file was opened. Set to invalidMode
	// if localFile isn't opened.
	mode p9.OpenFlags

	// ft is the fileType for this file.
	ft fileType

	// readDirMu protects against concurrent Readdir calls.
	readDirMu sync.Mutex

	// lastDirentOffset is the last offset returned by Readdir(). If another call
	// to Readdir is made at the same offset, the file doesn't need to be
	// repositioned. This is an important optimization because the caller must
	// always make one extra call to detect EOF (empty result, no error).
	lastDirentOffset uint64
}

var procSelfFD *fd.FD

// OpenProcSelfFD opens the /proc/self/fd directory, which will be used to
// reopen file descriptors.
func OpenProcSelfFD() error {
	d, err := syscall.Open("/proc/self/fd", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("error opening /proc/self/fd: %v", err)
	}
	procSelfFD = fd.New(d)
	return nil
}

func reopenProcFd(f *fd.FD, mode int) (*fd.FD, error) {
	d, err := syscall.Openat(int(procSelfFD.FD()), strconv.Itoa(f.FD()), mode&^syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}

	return fd.New(d), nil
}

func openAnyFileFromParent(parent *localFile, name string) (*fd.FD, string, error) {
	path := path.Join(parent.hostPath, name)
	f, err := openAnyFile(path, func(mode int) (*fd.FD, error) {
		return fd.OpenAt(parent.file, name, openFlags|mode, 0)
	})
	return f, path, err
}

// openAnyFile attempts to open the file in O_RDONLY and if it fails fallsback
// to O_PATH. 'path' is used for logging messages only. 'fn' is what does the
// actual file open and is customizable by the caller.
func openAnyFile(path string, fn func(mode int) (*fd.FD, error)) (*fd.FD, error) {
	// Attempt to open file in the following mode in order:
	//   1. RDONLY | NONBLOCK: for all files, works for directories and ro mounts too.
	//      Use non-blocking to prevent getting stuck inside open(2) for FIFOs. This option
	//      has no effect on regular files.
	//   2. PATH: for symlinks
	modes := []int{syscall.O_RDONLY | syscall.O_NONBLOCK, unix.O_PATH}

	var err error
	var file *fd.FD
	for i, mode := range modes {
		file, err = fn(mode)
		if err == nil {
			// openat succeeded, we're done.
			break
		}
		switch e := extractErrno(err); e {
		case syscall.ENOENT:
			// File doesn't exist, no point in retrying.
			return nil, e
		}
		// openat failed. Try again with next mode, preserving 'err' in case this
		// was the last attempt.
		log.Debugf("Attempt %d to open file failed, mode: %#x, path: %q, err: %v", i, openFlags|mode, path, err)
	}
	if err != nil {
		// All attempts to open file have failed, return the last error.
		log.Debugf("Failed to open file, path: %q, err: %v", path, err)
		return nil, extractErrno(err)
	}

	return file, nil
}

func getSupportedFileType(stat syscall.Stat_t) (fileType, error) {
	var ft fileType
	switch stat.Mode & syscall.S_IFMT {
	case syscall.S_IFREG:
		ft = regular
	case syscall.S_IFDIR:
		ft = directory
	case syscall.S_IFLNK:
		ft = symlink
	case syscall.S_IFSOCK:
		ft = socket
	default:
		return unknown, syscall.EPERM
	}
	return ft, nil
}

func newLocalFile(a *attachPoint, file *fd.FD, path string, stat syscall.Stat_t) (*localFile, error) {
	ft, err := getSupportedFileType(stat)
	if err != nil {
		return nil, err
	}

	return &localFile{
		attachPoint: a,
		hostPath:    path,
		file:        file,
		mode:        invalidMode,
		ft:          ft,
	}, nil
}

// newFDMaybe creates a fd.FD from a file, dup'ing the FD and setting it as
// non-blocking. If anything fails, returns nil. It's better to have a file
// without host FD, than to fail the operation.
func newFDMaybe(file *fd.FD) *fd.FD {
	dupFD, err := syscall.Dup(file.FD())
	// Technically, the runtime may call the finalizer on file as soon as
	// FD() returns.
	runtime.KeepAlive(file)
	if err != nil {
		return nil
	}
	dup := fd.New(dupFD)

	// fd is blocking; non-blocking is required.
	if err := syscall.SetNonblock(dup.FD(), true); err != nil {
		dup.Close()
		return nil
	}
	return dup
}

func stat(fd int) (syscall.Stat_t, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return syscall.Stat_t{}, err
	}
	return stat, nil
}

func fchown(fd int, uid p9.UID, gid p9.GID) error {
	return syscall.Fchownat(fd, "", int(uid), int(gid), linux.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

// Open implements p9.File.
func (l *localFile) Open(mode p9.OpenFlags) (*fd.FD, p9.QID, uint32, error) {
	if l.isOpen() {
		panic(fmt.Sprintf("attempting to open already opened file: %q", l.hostPath))
	}

	// Check if control file can be used or if a new open must be created.
	var newFile *fd.FD
	if mode == p9.ReadOnly {
		log.Debugf("Open reusing control file, mode: %v, %q", mode, l.hostPath)
		newFile = l.file
	} else {
		// Ideally reopen would call name_to_handle_at (with empty name) and
		// open_by_handle_at to reopen the file without using 'hostPath'. However,
		// name_to_handle_at and open_by_handle_at aren't supported by overlay2.
		log.Debugf("Open reopening file, mode: %v, %q", mode, l.hostPath)
		var err error
		newFile, err = reopenProcFd(l.file, openFlags|mode.OSFlags())
		if err != nil {
			return nil, p9.QID{}, 0, extractErrno(err)
		}
	}

	stat, err := stat(newFile.FD())
	if err != nil {
		if newFile != l.file {
			newFile.Close()
		}
		return nil, p9.QID{}, 0, extractErrno(err)
	}

	var fd *fd.FD
	if stat.Mode&syscall.S_IFMT == syscall.S_IFREG {
		// Donate FD for regular files only.
		fd = newFDMaybe(newFile)
	}

	// Close old file in case a new one was created.
	if newFile != l.file {
		if err := l.file.Close(); err != nil {
			log.Warningf("Error closing file %q: %v", l.hostPath, err)
		}
		l.file = newFile
	}
	l.mode = mode
	return fd, l.attachPoint.makeQID(stat), 0, nil
}

// Create implements p9.File.
func (l *localFile) Create(name string, mode p9.OpenFlags, perm p9.FileMode, uid p9.UID, gid p9.GID) (*fd.FD, p9.File, p9.QID, uint32, error) {
	conf := l.attachPoint.conf
	if conf.ROMount {
		if conf.PanicOnWrite {
			panic("attempt to write to RO mount")
		}
		return nil, nil, p9.QID{}, 0, syscall.EBADF
	}

	// 'file' may be used for other operations (e.g. Walk), so read access is
	// always added to flags. Note that resulting file might have a wider mode
	// than needed for each particular case.
	flags := openFlags | syscall.O_CREAT | syscall.O_EXCL
	if mode == p9.WriteOnly {
		flags |= syscall.O_RDWR
	} else {
		flags |= mode.OSFlags()
	}

	child, err := fd.OpenAt(l.file, name, flags, uint32(perm.Permissions()))
	if err != nil {
		return nil, nil, p9.QID{}, 0, extractErrno(err)
	}
	cu := specutils.MakeCleanup(func() {
		child.Close()
		// Best effort attempt to remove the file in case of failure.
		if err := syscall.Unlinkat(l.file.FD(), name); err != nil {
			log.Warningf("error unlinking file %q after failure: %v", path.Join(l.hostPath, name), err)
		}
	})
	defer cu.Clean()

	if err := fchown(child.FD(), uid, gid); err != nil {
		return nil, nil, p9.QID{}, 0, extractErrno(err)
	}
	stat, err := stat(child.FD())
	if err != nil {
		return nil, nil, p9.QID{}, 0, extractErrno(err)
	}

	c := &localFile{
		attachPoint: l.attachPoint,
		hostPath:    path.Join(l.hostPath, name),
		file:        child,
		mode:        mode,
	}

	cu.Release()
	return newFDMaybe(c.file), c, l.attachPoint.makeQID(stat), 0, nil
}

// Mkdir implements p9.File.
func (l *localFile) Mkdir(name string, perm p9.FileMode, uid p9.UID, gid p9.GID) (p9.QID, error) {
	conf := l.attachPoint.conf
	if conf.ROMount {
		if conf.PanicOnWrite {
			panic("attempt to write to RO mount")
		}
		return p9.QID{}, syscall.EBADF
	}

	if err := syscall.Mkdirat(l.file.FD(), name, uint32(perm.Permissions())); err != nil {
		return p9.QID{}, extractErrno(err)
	}
	cu := specutils.MakeCleanup(func() {
		// Best effort attempt to remove the dir in case of failure.
		if err := unix.Unlinkat(l.file.FD(), name, unix.AT_REMOVEDIR); err != nil {
			log.Warningf("error unlinking dir %q after failure: %v", path.Join(l.hostPath, name), err)
		}
	})
	defer cu.Clean()

	// Open directory to change ownership and stat it.
	flags := syscall.O_DIRECTORY | syscall.O_RDONLY | openFlags
	f, err := fd.OpenAt(l.file, name, flags, 0)
	if err != nil {
		return p9.QID{}, extractErrno(err)
	}
	defer f.Close()

	if err := fchown(f.FD(), uid, gid); err != nil {
		return p9.QID{}, extractErrno(err)
	}
	stat, err := stat(f.FD())
	if err != nil {
		return p9.QID{}, extractErrno(err)
	}

	cu.Release()
	return l.attachPoint.makeQID(stat), nil
}

// Walk implements p9.File.
func (l *localFile) Walk(names []string) ([]p9.QID, p9.File, error) {
	// Duplicate current file if 'names' is empty.
	if len(names) == 0 {
		newFile, err := openAnyFile(l.hostPath, func(mode int) (*fd.FD, error) {
			return reopenProcFd(l.file, openFlags|mode)
		})
		if err != nil {
			return nil, nil, extractErrno(err)
		}

		stat, err := stat(newFile.FD())
		if err != nil {
			newFile.Close()
			return nil, nil, extractErrno(err)
		}

		c := &localFile{
			attachPoint: l.attachPoint,
			hostPath:    l.hostPath,
			file:        newFile,
			mode:        invalidMode,
		}
		return []p9.QID{l.attachPoint.makeQID(stat)}, c, nil
	}

	var qids []p9.QID
	last := l
	for _, name := range names {
		f, path, err := openAnyFileFromParent(last, name)
		if last != l {
			last.Close()
		}
		if err != nil {
			return nil, nil, extractErrno(err)
		}
		stat, err := stat(f.FD())
		if err != nil {
			f.Close()
			return nil, nil, extractErrno(err)
		}
		c, err := newLocalFile(last.attachPoint, f, path, stat)
		if err != nil {
			f.Close()
			return nil, nil, extractErrno(err)
		}

		qids = append(qids, l.attachPoint.makeQID(stat))
		last = c
	}
	return qids, last, nil
}

// StatFS implements p9.File.
func (l *localFile) StatFS() (p9.FSStat, error) {
	var s syscall.Statfs_t
	if err := syscall.Fstatfs(l.file.FD(), &s); err != nil {
		return p9.FSStat{}, extractErrno(err)
	}

	// Populate with what's available.
	return p9.FSStat{
		Type:            uint32(s.Type),
		BlockSize:       uint32(s.Bsize),
		Blocks:          s.Blocks,
		BlocksFree:      s.Bfree,
		BlocksAvailable: s.Bavail,
		Files:           s.Files,
		FilesFree:       s.Ffree,
		NameLength:      uint32(s.Namelen),
	}, nil
}

// FSync implements p9.File.
func (l *localFile) FSync() error {
	if !l.isOpen() {
		return syscall.EBADF
	}
	if err := syscall.Fsync(l.file.FD()); err != nil {
		return extractErrno(err)
	}
	return nil
}

// GetAttr implements p9.File.
func (l *localFile) GetAttr(_ p9.AttrMask) (p9.QID, p9.AttrMask, p9.Attr, error) {
	stat, err := stat(l.file.FD())
	if err != nil {
		return p9.QID{}, p9.AttrMask{}, p9.Attr{}, extractErrno(err)
	}

	attr := p9.Attr{
		Mode:             p9.FileMode(stat.Mode),
		UID:              p9.UID(stat.Uid),
		GID:              p9.GID(stat.Gid),
		NLink:            stat.Nlink,
		RDev:             stat.Rdev,
		Size:             uint64(stat.Size),
		BlockSize:        uint64(stat.Blksize),
		Blocks:           uint64(stat.Blocks),
		ATimeSeconds:     uint64(stat.Atim.Sec),
		ATimeNanoSeconds: uint64(stat.Atim.Nsec),
		MTimeSeconds:     uint64(stat.Mtim.Sec),
		MTimeNanoSeconds: uint64(stat.Mtim.Nsec),
		CTimeSeconds:     uint64(stat.Ctim.Sec),
		CTimeNanoSeconds: uint64(stat.Ctim.Nsec),
	}
	valid := p9.AttrMask{
		Mode:   true,
		UID:    true,
		GID:    true,
		NLink:  true,
		RDev:   true,
		Size:   true,
		Blocks: true,
		ATime:  true,
		MTime:  true,
		CTime:  true,
	}

	return l.attachPoint.makeQID(stat), valid, attr, nil
}

// SetAttr implements p9.File. Due to mismatch in file API, options
// cannot be changed atomically and user may see partial changes when
// an error happens.
func (l *localFile) SetAttr(valid p9.SetAttrMask, attr p9.SetAttr) error {
	conf := l.attachPoint.conf
	if conf.ROMount {
		if conf.PanicOnWrite {
			panic("attempt to write to RO mount")
		}
		return syscall.EBADF
	}

	allowed := p9.SetAttrMask{
		Permissions:        true,
		UID:                true,
		GID:                true,
		Size:               true,
		ATime:              true,
		MTime:              true,
		ATimeNotSystemTime: true,
		MTimeNotSystemTime: true,
	}

	if valid.Empty() {
		// Nothing to do.
		return nil
	}

	// Handle all the sanity checks up front so that the client gets a
	// consistent result that is not attribute dependent.
	if !valid.IsSubsetOf(allowed) {
		log.Warningf("SetAttr() failed for %q, mask: %v", l.hostPath, valid)
		return syscall.EPERM
	}

	// Check if it's possible to use cached file, or if another one needs to be
	// opened for write.
	f := l.file
	if l.ft == regular && l.mode != p9.WriteOnly && l.mode != p9.ReadWrite {
		var err error
		f, err = reopenProcFd(l.file, openFlags|os.O_WRONLY)
		if err != nil {
			return extractErrno(err)
		}
		defer f.Close()
	}

	// The semantics are to either return an error if no changes were made,
	// or no error if *all* changes were made. Well, this can be impossible
	// if the filesystem rejects at least one of the changes, especially
	// since some operations are not easy to undo atomically.
	//
	// This could be made better if SetAttr actually returned the changes
	// it did make, so the client can at least know what has changed. So
	// we at least attempt to make all of the changes and return a generic
	// error if any of them fails, which at least doesn't bias any change
	// over another.
	var err error
	if valid.Permissions {
		if cerr := syscall.Fchmod(f.FD(), uint32(attr.Permissions)); cerr != nil {
			log.Debugf("SetAttr fchmod failed %q, err: %v", l.hostPath, cerr)
			err = extractErrno(cerr)
		}
	}

	if valid.Size {
		if terr := syscall.Ftruncate(f.FD(), int64(attr.Size)); terr != nil {
			log.Debugf("SetAttr ftruncate failed %q, err: %v", l.hostPath, terr)
			err = extractErrno(terr)
		}
	}

	if valid.ATime || valid.MTime {
		utimes := [2]syscall.Timespec{
			{Sec: 0, Nsec: linux.UTIME_OMIT},
			{Sec: 0, Nsec: linux.UTIME_OMIT},
		}
		if valid.ATime {
			if valid.ATimeNotSystemTime {
				utimes[0].Sec = int64(attr.ATimeSeconds)
				utimes[0].Nsec = int64(attr.ATimeNanoSeconds)
			} else {
				utimes[0].Nsec = linux.UTIME_NOW
			}
		}
		if valid.MTime {
			if valid.MTimeNotSystemTime {
				utimes[1].Sec = int64(attr.MTimeSeconds)
				utimes[1].Nsec = int64(attr.MTimeNanoSeconds)
			} else {
				utimes[1].Nsec = linux.UTIME_NOW
			}
		}

		if l.ft == symlink {
			// utimensat operates different that other syscalls. To operate on a
			// symlink it *requires* AT_SYMLINK_NOFOLLOW with dirFD and a non-empty
			// name.
			parent, err := syscall.Open(path.Dir(l.hostPath), openFlags|unix.O_PATH, 0)
			if err != nil {
				return extractErrno(err)
			}
			defer syscall.Close(parent)

			if terr := utimensat(parent, path.Base(l.hostPath), utimes, linux.AT_SYMLINK_NOFOLLOW); terr != nil {
				log.Debugf("SetAttr utimens failed %q, err: %v", l.hostPath, terr)
				err = extractErrno(terr)
			}
		} else {
			// Directories and regular files can operate directly on the fd
			// using empty name.
			if terr := utimensat(f.FD(), "", utimes, 0); terr != nil {
				log.Debugf("SetAttr utimens failed %q, err: %v", l.hostPath, terr)
				err = extractErrno(terr)
			}
		}
	}

	if valid.UID || valid.GID {
		uid := -1
		if valid.UID {
			uid = int(attr.UID)
		}
		gid := -1
		if valid.GID {
			gid = int(attr.GID)
		}
		if oerr := syscall.Fchownat(f.FD(), "", uid, gid, linux.AT_EMPTY_PATH|linux.AT_SYMLINK_NOFOLLOW); oerr != nil {
			log.Debugf("SetAttr fchownat failed %q, err: %v", l.hostPath, oerr)
			err = extractErrno(oerr)
		}
	}

	return err
}

// Allocate implements p9.File.
func (l *localFile) Allocate(mode p9.AllocateMode, offset, length uint64) error {
	if !l.isOpen() {
		return syscall.EBADF
	}

	if err := syscall.Fallocate(l.file.FD(), mode.ToLinux(), int64(offset), int64(length)); err != nil {
		return extractErrno(err)
	}
	return nil
}

// Rename implements p9.File; this should never be called.
func (l *localFile) Rename(p9.File, string) error {
	panic("rename called directly")
}

// RenameAt implements p9.File.RenameAt.
func (l *localFile) RenameAt(oldName string, directory p9.File, newName string) error {
	conf := l.attachPoint.conf
	if conf.ROMount {
		if conf.PanicOnWrite {
			panic("attempt to write to RO mount")
		}
		return syscall.EBADF
	}

	newParent := directory.(*localFile)
	if err := renameat(l.file.FD(), oldName, newParent.file.FD(), newName); err != nil {
		return extractErrno(err)
	}
	return nil
}

// ReadAt implements p9.File.
func (l *localFile) ReadAt(p []byte, offset uint64) (int, error) {
	if l.mode != p9.ReadOnly && l.mode != p9.ReadWrite {
		return 0, syscall.EBADF
	}
	if !l.isOpen() {
		return 0, syscall.EBADF
	}

	r, err := l.file.ReadAt(p, int64(offset))
	switch err {
	case nil, io.EOF:
		return r, nil
	default:
		return r, extractErrno(err)
	}
}

// WriteAt implements p9.File.
func (l *localFile) WriteAt(p []byte, offset uint64) (int, error) {
	if l.mode != p9.WriteOnly && l.mode != p9.ReadWrite {
		return 0, syscall.EBADF
	}
	if !l.isOpen() {
		return 0, syscall.EBADF
	}

	w, err := l.file.WriteAt(p, int64(offset))
	if err != nil {
		return w, extractErrno(err)
	}
	return w, nil
}

// Symlink implements p9.File.
func (l *localFile) Symlink(target, newName string, uid p9.UID, gid p9.GID) (p9.QID, error) {
	conf := l.attachPoint.conf
	if conf.ROMount {
		if conf.PanicOnWrite {
			panic("attempt to write to RO mount")
		}
		return p9.QID{}, syscall.EBADF
	}

	if err := unix.Symlinkat(target, l.file.FD(), newName); err != nil {
		return p9.QID{}, extractErrno(err)
	}
	cu := specutils.MakeCleanup(func() {
		// Best effort attempt to remove the symlink in case of failure.
		if err := syscall.Unlinkat(l.file.FD(), newName); err != nil {
			log.Warningf("error unlinking file %q after failure: %v", path.Join(l.hostPath, newName), err)
		}
	})
	defer cu.Clean()

	// Open symlink to change ownership and stat it.
	f, err := fd.OpenAt(l.file, newName, unix.O_PATH|openFlags, 0)
	if err != nil {
		return p9.QID{}, extractErrno(err)
	}
	defer f.Close()

	if err := fchown(f.FD(), uid, gid); err != nil {
		return p9.QID{}, extractErrno(err)
	}
	stat, err := stat(f.FD())
	if err != nil {
		return p9.QID{}, extractErrno(err)
	}

	cu.Release()
	return l.attachPoint.makeQID(stat), nil
}

// Link implements p9.File.
func (l *localFile) Link(target p9.File, newName string) error {
	conf := l.attachPoint.conf
	if conf.ROMount {
		if conf.PanicOnWrite {
			panic("attempt to write to RO mount")
		}
		return syscall.EBADF
	}

	targetFile := target.(*localFile)
	if err := unix.Linkat(targetFile.file.FD(), "", l.file.FD(), newName, linux.AT_EMPTY_PATH); err != nil {
		return extractErrno(err)
	}
	return nil
}

// Mknod implements p9.File.
//
// Not implemented.
func (*localFile) Mknod(_ string, _ p9.FileMode, _ uint32, _ uint32, _ p9.UID, _ p9.GID) (p9.QID, error) {
	// From mknod(2) man page:
	// "EPERM: [...] if the filesystem containing pathname does not support
	// the type of node requested."
	return p9.QID{}, syscall.EPERM
}

// UnlinkAt implements p9.File.
func (l *localFile) UnlinkAt(name string, flags uint32) error {
	conf := l.attachPoint.conf
	if conf.ROMount {
		if conf.PanicOnWrite {
			panic("attempt to write to RO mount")
		}
		return syscall.EBADF
	}

	if err := unix.Unlinkat(l.file.FD(), name, int(flags)); err != nil {
		return extractErrno(err)
	}
	return nil
}

// Readdir implements p9.File.
func (l *localFile) Readdir(offset uint64, count uint32) ([]p9.Dirent, error) {
	if l.mode != p9.ReadOnly && l.mode != p9.ReadWrite {
		return nil, syscall.EBADF
	}
	if !l.isOpen() {
		return nil, syscall.EBADF
	}

	// Readdirnames is a cursor over directories, so seek back to 0 to ensure it's
	// reading all directory contents. Take a lock because this operation is
	// stateful.
	l.readDirMu.Lock()
	defer l.readDirMu.Unlock()

	skip := uint64(0)

	// Check if the file is at the correct position already. If not, seek to the
	// beginning and read the entire directory again.
	if l.lastDirentOffset != offset {
		if _, err := syscall.Seek(l.file.FD(), 0, 0); err != nil {
			return nil, extractErrno(err)
		}
		skip = offset
	}

	dirents, err := l.readDirent(l.file.FD(), offset, count, skip)
	if err == nil {
		// On success, remember the offset that was returned at the current
		// position.
		l.lastDirentOffset = offset + uint64(len(dirents))
	} else {
		// On failure, the state is unknown, force call to seek() next time.
		l.lastDirentOffset = math.MaxUint64
	}
	return dirents, err
}

func (l *localFile) readDirent(f int, offset uint64, count uint32, skip uint64) ([]p9.Dirent, error) {
	// Limit 'count' to cap the slice size that is returned.
	const maxCount = 100000
	if count > maxCount {
		count = maxCount
	}

	dirents := make([]p9.Dirent, 0, count)

	// Pre-allocate buffers that will be reused to get partial results.
	direntsBuf := make([]byte, 8192)
	names := make([]string, 0, 100)

	end := offset + uint64(count)
	for offset < end {
		dirSize, err := syscall.ReadDirent(f, direntsBuf)
		if err != nil {
			return dirents, err
		}
		if dirSize <= 0 {
			return dirents, nil
		}

		names := names[:0]
		_, _, names = syscall.ParseDirent(direntsBuf[:dirSize], -1, names)

		// Skip over entries that the caller is not interested in.
		if skip > 0 {
			if skip > uint64(len(names)) {
				skip -= uint64(len(names))
				names = names[:0]
			} else {
				names = names[skip:]
				skip = 0
			}
		}
		for _, name := range names {
			stat, err := statAt(l.file.FD(), name)
			if err != nil {
				log.Warningf("Readdir is skipping file with failed stat %q, err: %v", l.hostPath, err)
				continue
			}
			qid := l.attachPoint.makeQID(stat)
			offset++
			dirents = append(dirents, p9.Dirent{
				QID:    qid,
				Type:   qid.Type,
				Name:   name,
				Offset: offset,
			})
		}
	}
	return dirents, nil
}

// Readlink implements p9.File.
func (l *localFile) Readlink() (string, error) {
	// Shamelessly stolen from os.Readlink (added upper bound limit to buffer).
	const limit = 1024 * 1024
	for len := 128; len < limit; len *= 2 {
		b := make([]byte, len)
		n, err := unix.Readlinkat(l.file.FD(), "", b)
		if err != nil {
			return "", extractErrno(err)
		}
		if n < len {
			return string(b[:n]), nil
		}
	}
	return "", syscall.ENOMEM
}

// Flush implements p9.File.
func (l *localFile) Flush() error {
	return nil
}

// Connect implements p9.File.
func (l *localFile) Connect(p9.ConnectFlags) (*fd.FD, error) {
	return fd.OpenUnix(l.hostPath)
}

// Close implements p9.File.
func (l *localFile) Close() error {
	l.mode = invalidMode
	err := l.file.Close()
	l.file = nil
	return err
}

func (l *localFile) isOpen() bool {
	return l.mode != invalidMode
}

// Renamed implements p9.Renamed.
func (l *localFile) Renamed(newDir p9.File, newName string) {
	l.hostPath = path.Join(newDir.(*localFile).hostPath, newName)
}

// extractErrno tries to determine the errno.
func extractErrno(err error) syscall.Errno {
	if err == nil {
		// This should never happen. The likely result will be that
		// some user gets the frustrating "error: SUCCESS" message.
		log.Warningf("extractErrno called with nil error!")
		return 0
	}

	switch err {
	case os.ErrNotExist:
		return syscall.ENOENT
	case os.ErrExist:
		return syscall.EEXIST
	case os.ErrPermission:
		return syscall.EACCES
	case os.ErrInvalid:
		return syscall.EINVAL
	}

	// See if it's an errno or a common wrapped error.
	switch e := err.(type) {
	case syscall.Errno:
		return e
	case *os.PathError:
		return extractErrno(e.Err)
	case *os.LinkError:
		return extractErrno(e.Err)
	case *os.SyscallError:
		return extractErrno(e.Err)
	}

	// Fall back to EIO.
	log.Debugf("Unknown error: %v, defaulting to EIO", err)
	return syscall.EIO
}
