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
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// invalidMode is set to a value that doesn't match any other valid
	// modes to ensure an unopened/closed file fails all mode checks.
	invalidMode = p9.OpenFlags(math.MaxUint32)

	openFlags = unix.O_NOFOLLOW | unix.O_CLOEXEC

	allowedOpenFlags = unix.O_TRUNC
)

// verityXattrs are the extended attributes used by verity file system.
var verityXattrs = map[string]struct{}{
	"user.merkle.offset":         {},
	"user.merkle.size":           {},
	"user.merkle.childrenOffset": {},
	"user.merkle.childrenSize":   {},
}

// join is equivalent to path.Join() but skips path.Clean() which is expensive.
func join(parent, child string) string {
	return parent + "/" + child
}

// Config sets configuration options for each attach point.
type Config struct {
	// ROMount is set to true if this is a readonly mount.
	ROMount bool

	// PanicOnWrite panics on attempts to write to RO mounts.
	PanicOnWrite bool

	// HostUDS signals whether the gofer can mount a host's UDS.
	HostUDS bool

	// EnableVerityXattr allows access to extended attributes used by the
	// verity file system.
	EnableVerityXattr bool
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
	a.attachedMu.Lock()
	defer a.attachedMu.Unlock()

	if a.attached {
		return nil, fmt.Errorf("attach point already attached, prefix: %s", a.prefix)
	}

	f, readable, err := openAnyFile(a.prefix, func(mode int) (*fd.FD, error) {
		return fd.Open(a.prefix, openFlags|mode, 0)
	})
	if err != nil {
		return nil, fmt.Errorf("unable to open %q: %v", a.prefix, err)
	}

	stat, err := fstat(f.FD())
	if err != nil {
		return nil, fmt.Errorf("unable to stat %q: %v", a.prefix, err)
	}

	lf, err := newLocalFile(a, f, a.prefix, readable, &stat)
	if err != nil {
		return nil, fmt.Errorf("unable to create localFile %q: %v", a.prefix, err)
	}
	a.attached = true
	return lf, nil
}

// makeQID returns a unique QID for the given stat buffer.
func (a *attachPoint) makeQID(stat *unix.Stat_t) p9.QID {
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
	return p9.QID{
		Type: p9.FileMode(stat.Mode).QIDType(),
		Path: ino,
	}
}

// localFile implements p9.File wrapping a local file. The underlying file
// is opened during Walk() and stored in 'file' to be used with other
// operations. The file is opened as readonly, unless it's a symlink or there is
// no read access, which requires O_PATH.
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
// multiple files are only being opened for read (esp. startup).
//
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
// The few exceptions where it cannot be done are: utimensat on symlinks, and
// Connect() for the socket address.
type localFile struct {
	p9.DisallowClientCalls

	// attachPoint is the attachPoint that serves this localFile.
	attachPoint *attachPoint

	// hostPath is the full path to the host file. It can be used for logging and
	// the few cases where full path is required to operation the host file. In
	// all other cases, use "file" directly.
	//
	// Note: it's safely updated by the Renamed hook.
	hostPath string

	// file is opened when localFile is created and it's never nil. It may be
	// reopened if the Open() mode is wider than the mode the file was originally
	// opened with.
	file *fd.FD

	// controlReadable tells whether 'file' was opened with read permissions
	// during a walk.
	controlReadable bool

	// mode is the mode in which the file was opened. Set to invalidMode
	// if localFile isn't opened.
	mode p9.OpenFlags

	// fileType for this file. It is equivalent to:
	// unix.Stat_t.Mode & unix.S_IFMT
	fileType uint32

	qid p9.QID

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
	d, err := unix.Open("/proc/self/fd", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("error opening /proc/self/fd: %v", err)
	}
	procSelfFD = fd.New(d)
	return nil
}

func reopenProcFd(f *fd.FD, mode int) (*fd.FD, error) {
	d, err := unix.Openat(int(procSelfFD.FD()), strconv.Itoa(f.FD()), mode&^unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}

	return fd.New(d), nil
}

func openAnyFileFromParent(parent *localFile, name string) (*fd.FD, string, bool, error) {
	pathDebug := join(parent.hostPath, name)
	f, readable, err := openAnyFile(pathDebug, func(mode int) (*fd.FD, error) {
		return fd.OpenAt(parent.file, name, openFlags|mode, 0)
	})
	return f, pathDebug, readable, err
}

// openAnyFile attempts to open the file in O_RDONLY. If it fails, falls back
// to O_PATH. 'path' is used for logging messages only. 'fn' is what does the
// actual file open and is customizable by the caller.
func openAnyFile(pathDebug string, fn func(mode int) (*fd.FD, error)) (*fd.FD, bool, error) {
	// Attempt to open file in the following mode in order:
	//   1. RDONLY | NONBLOCK: for all files, directories, ro mounts, FIFOs.
	//      Use non-blocking to prevent getting stuck inside open(2) for
	//      FIFOs. This option has no effect on regular files.
	//   2. PATH: for symlinks, sockets.
	options := []struct {
		mode     int
		readable bool
	}{
		{
			mode:     unix.O_RDONLY | unix.O_NONBLOCK,
			readable: true,
		},
		{
			mode:     unix.O_PATH,
			readable: false,
		},
	}

	var err error
	for i, option := range options {
		var file *fd.FD
		file, err = fn(option.mode)
		if err == nil {
			// Succeeded opening the file, we're done.
			return file, option.readable, nil
		}
		switch e := extractErrno(err); e {
		case unix.ENOENT:
			// File doesn't exist, no point in retrying.
			return nil, false, e
		}
		// File failed to open. Try again with next mode, preserving 'err' in case
		// this was the last attempt.
		log.Debugf("Attempt %d to open file failed, mode: %#x, path: %q, err: %v", i, openFlags|option.mode, pathDebug, err)
	}
	// All attempts to open file have failed, return the last error.
	log.Debugf("Failed to open file, path: %q, err: %v", pathDebug, err)
	return nil, false, extractErrno(err)
}

func checkSupportedFileType(mode uint32, permitSocket bool) error {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG, unix.S_IFDIR, unix.S_IFLNK:
		return nil

	case unix.S_IFSOCK:
		if !permitSocket {
			return unix.EPERM
		}
		return nil

	default:
		return unix.EPERM
	}
}

func newLocalFile(a *attachPoint, file *fd.FD, path string, readable bool, stat *unix.Stat_t) (*localFile, error) {
	if err := checkSupportedFileType(stat.Mode, a.conf.HostUDS); err != nil {
		return nil, err
	}

	return &localFile{
		attachPoint:     a,
		hostPath:        path,
		file:            file,
		mode:            invalidMode,
		fileType:        stat.Mode & unix.S_IFMT,
		qid:             a.makeQID(stat),
		controlReadable: readable,
	}, nil
}

// newFDMaybe creates a fd.FD from a file, dup'ing the FD and setting it as
// non-blocking. If anything fails, returns nil. It's better to have a file
// without host FD, than to fail the operation.
func newFDMaybe(file *fd.FD) *fd.FD {
	dupFD, err := unix.Dup(file.FD())
	// Technically, the runtime may call the finalizer on file as soon as
	// FD() returns.
	runtime.KeepAlive(file)
	if err != nil {
		return nil
	}
	dup := fd.New(dupFD)

	// fd is blocking; non-blocking is required.
	if err := unix.SetNonblock(dup.FD(), true); err != nil {
		_ = dup.Close()
		return nil
	}
	return dup
}

func fstat(fd int) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return unix.Stat_t{}, err
	}
	return stat, nil
}

func fchown(fd int, uid p9.UID, gid p9.GID) error {
	return unix.Fchownat(fd, "", int(uid), int(gid), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

func setOwnerIfNeeded(fd int, uid p9.UID, gid p9.GID) (unix.Stat_t, error) {
	stat, err := fstat(fd)
	if err != nil {
		return unix.Stat_t{}, err
	}

	// Change ownership if not set accordinly.
	if uint32(uid) != stat.Uid || uint32(gid) != stat.Gid {
		if err := fchown(fd, uid, gid); err != nil {
			return unix.Stat_t{}, err
		}
		stat.Uid = uint32(uid)
		stat.Gid = uint32(gid)
	}
	return stat, nil
}

// Open implements p9.File.
func (l *localFile) Open(flags p9.OpenFlags) (*fd.FD, p9.QID, uint32, error) {
	if l.isOpen() {
		panic(fmt.Sprintf("attempting to open already opened file: %q", l.hostPath))
	}
	mode := flags & p9.OpenFlagsModeMask
	if mode == p9.WriteOnly || mode == p9.ReadWrite || flags&p9.OpenTruncate != 0 {
		if err := l.checkROMount(); err != nil {
			return nil, p9.QID{}, 0, err
		}
	}

	// Check if control file can be used or if a new open must be created.
	var newFile *fd.FD
	if mode == p9.ReadOnly && l.controlReadable && flags.OSFlags()&allowedOpenFlags == 0 {
		log.Debugf("Open reusing control file, flags: %v, %q", flags, l.hostPath)
		newFile = l.file
	} else {
		// Ideally reopen would call name_to_handle_at (with empty name) and
		// open_by_handle_at to reopen the file without using 'hostPath'. However,
		// name_to_handle_at and open_by_handle_at aren't supported by overlay2.
		log.Debugf("Open reopening file, flags: %v, %q", flags, l.hostPath)
		var err error
		osFlags := flags.OSFlags() & (unix.O_ACCMODE | allowedOpenFlags)
		newFile, err = reopenProcFd(l.file, openFlags|osFlags)
		if err != nil {
			return nil, p9.QID{}, 0, extractErrno(err)
		}
	}

	var fd *fd.FD
	if l.fileType == unix.S_IFREG {
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
	return fd, l.qid, 0, nil
}

// Create implements p9.File.
func (l *localFile) Create(name string, p9Flags p9.OpenFlags, perm p9.FileMode, uid p9.UID, gid p9.GID) (*fd.FD, p9.File, p9.QID, uint32, error) {
	if err := l.checkROMount(); err != nil {
		return nil, nil, p9.QID{}, 0, err
	}

	// Set file creation flags, plus allowed open flags from caller.
	osFlags := openFlags | unix.O_CREAT | unix.O_EXCL
	osFlags |= p9Flags.OSFlags() & allowedOpenFlags

	// 'file' may be used for other operations (e.g. Walk), so read access is
	// always added to flags. Note that resulting file might have a wider mode
	// than needed for each particular case.
	mode := p9Flags & p9.OpenFlagsModeMask
	if mode == p9.WriteOnly {
		osFlags |= unix.O_RDWR
	} else {
		osFlags |= mode.OSFlags()
	}

	child, err := fd.OpenAt(l.file, name, osFlags, uint32(perm.Permissions()))
	if err != nil {
		return nil, nil, p9.QID{}, 0, extractErrno(err)
	}
	cu := cleanup.Make(func() {
		_ = child.Close()
		// Best effort attempt to remove the file in case of failure.
		if err := unix.Unlinkat(l.file.FD(), name, 0); err != nil {
			log.Warningf("error unlinking file %q after failure: %v", path.Join(l.hostPath, name), err)
		}
	})
	defer cu.Clean()

	stat, err := setOwnerIfNeeded(child.FD(), uid, gid)
	if err != nil {
		return nil, nil, p9.QID{}, 0, extractErrno(err)
	}

	c := &localFile{
		attachPoint: l.attachPoint,
		hostPath:    join(l.hostPath, name),
		file:        child,
		mode:        mode,
		fileType:    unix.S_IFREG,
		qid:         l.attachPoint.makeQID(&stat),
	}

	cu.Release()
	return newFDMaybe(c.file), c, c.qid, 0, nil
}

// Mkdir implements p9.File.
func (l *localFile) Mkdir(name string, perm p9.FileMode, uid p9.UID, gid p9.GID) (p9.QID, error) {
	if err := l.checkROMount(); err != nil {
		return p9.QID{}, err
	}

	if err := unix.Mkdirat(l.file.FD(), name, uint32(perm.Permissions())); err != nil {
		return p9.QID{}, extractErrno(err)
	}
	cu := cleanup.Make(func() {
		// Best effort attempt to remove the dir in case of failure.
		if err := unix.Unlinkat(l.file.FD(), name, unix.AT_REMOVEDIR); err != nil {
			log.Warningf("error unlinking dir %q after failure: %v", path.Join(l.hostPath, name), err)
		}
	})
	defer cu.Clean()

	// Open directory to change ownership and stat it.
	flags := unix.O_DIRECTORY | unix.O_RDONLY | openFlags
	f, err := fd.OpenAt(l.file, name, flags, 0)
	if err != nil {
		return p9.QID{}, extractErrno(err)
	}
	defer f.Close()

	stat, err := setOwnerIfNeeded(f.FD(), uid, gid)
	if err != nil {
		return p9.QID{}, extractErrno(err)
	}

	cu.Release()
	return l.attachPoint.makeQID(&stat), nil
}

// Walk implements p9.File.
func (l *localFile) Walk(names []string) ([]p9.QID, p9.File, error) {
	qids, file, _, err := l.walk(names)
	return qids, file, err
}

// WalkGetAttr implements p9.File.
func (l *localFile) WalkGetAttr(names []string) ([]p9.QID, p9.File, p9.AttrMask, p9.Attr, error) {
	qids, file, stat, err := l.walk(names)
	if err != nil {
		return nil, nil, p9.AttrMask{}, p9.Attr{}, err
	}
	mask, attr := l.fillAttr(&stat)
	return qids, file, mask, attr, nil
}

func (l *localFile) walk(names []string) ([]p9.QID, p9.File, unix.Stat_t, error) {
	// Duplicate current file if 'names' is empty.
	if len(names) == 0 {
		newFile, readable, err := openAnyFile(l.hostPath, func(mode int) (*fd.FD, error) {
			return reopenProcFd(l.file, openFlags|mode)
		})
		if err != nil {
			return nil, nil, unix.Stat_t{}, extractErrno(err)
		}

		stat, err := fstat(newFile.FD())
		if err != nil {
			_ = newFile.Close()
			return nil, nil, unix.Stat_t{}, extractErrno(err)
		}

		c := &localFile{
			attachPoint:     l.attachPoint,
			hostPath:        l.hostPath,
			file:            newFile,
			mode:            invalidMode,
			fileType:        l.fileType,
			qid:             l.attachPoint.makeQID(&stat),
			controlReadable: readable,
		}
		return []p9.QID{c.qid}, c, stat, nil
	}

	qids := make([]p9.QID, 0, len(names))
	var lastStat unix.Stat_t
	last := l
	for _, name := range names {
		f, path, readable, err := openAnyFileFromParent(last, name)
		if last != l {
			_ = last.Close()
		}
		if err != nil {
			return nil, nil, unix.Stat_t{}, extractErrno(err)
		}
		lastStat, err = fstat(f.FD())
		if err != nil {
			_ = f.Close()
			return nil, nil, unix.Stat_t{}, extractErrno(err)
		}
		c, err := newLocalFile(last.attachPoint, f, path, readable, &lastStat)
		if err != nil {
			_ = f.Close()
			return nil, nil, unix.Stat_t{}, extractErrno(err)
		}

		qids = append(qids, c.qid)
		last = c
	}
	return qids, last, lastStat, nil
}

// StatFS implements p9.File.
func (l *localFile) StatFS() (p9.FSStat, error) {
	var s unix.Statfs_t
	if err := unix.Fstatfs(l.file.FD(), &s); err != nil {
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
		return unix.EBADF
	}
	if err := unix.Fsync(l.file.FD()); err != nil {
		return extractErrno(err)
	}
	return nil
}

// GetAttr implements p9.File.
func (l *localFile) GetAttr(_ p9.AttrMask) (p9.QID, p9.AttrMask, p9.Attr, error) {
	stat, err := fstat(l.file.FD())
	if err != nil {
		return p9.QID{}, p9.AttrMask{}, p9.Attr{}, extractErrno(err)
	}
	mask, attr := l.fillAttr(&stat)
	return l.qid, mask, attr, nil
}

func (l *localFile) fillAttr(stat *unix.Stat_t) (p9.AttrMask, p9.Attr) {
	attr := p9.Attr{
		Mode:             p9.FileMode(stat.Mode),
		UID:              p9.UID(stat.Uid),
		GID:              p9.GID(stat.Gid),
		NLink:            uint64(stat.Nlink),
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
	return valid, attr
}

// SetAttr implements p9.File. Due to mismatch in file API, options
// cannot be changed atomically and user may see partial changes when
// an error happens.
func (l *localFile) SetAttr(valid p9.SetAttrMask, attr p9.SetAttr) error {
	if err := l.checkROMount(); err != nil {
		return err
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
		return unix.EPERM
	}

	// Check if it's possible to use cached file, or if another one needs to be
	// opened for write.
	f := l.file
	if l.fileType == unix.S_IFREG && l.mode != p9.WriteOnly && l.mode != p9.ReadWrite {
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
		if cerr := unix.Fchmod(f.FD(), uint32(attr.Permissions)); cerr != nil {
			log.Debugf("SetAttr fchmod failed %q, err: %v", l.hostPath, cerr)
			err = extractErrno(cerr)
		}
	}

	if valid.Size {
		if terr := unix.Ftruncate(f.FD(), int64(attr.Size)); terr != nil {
			log.Debugf("SetAttr ftruncate failed %q, err: %v", l.hostPath, terr)
			err = extractErrno(terr)
		}
	}

	if valid.ATime || valid.MTime {
		utimes := [2]unix.Timespec{
			{Sec: 0, Nsec: unix.UTIME_OMIT},
			{Sec: 0, Nsec: unix.UTIME_OMIT},
		}
		if valid.ATime {
			if valid.ATimeNotSystemTime {
				utimes[0].Sec = int64(attr.ATimeSeconds)
				utimes[0].Nsec = int64(attr.ATimeNanoSeconds)
			} else {
				utimes[0].Nsec = unix.UTIME_NOW
			}
		}
		if valid.MTime {
			if valid.MTimeNotSystemTime {
				utimes[1].Sec = int64(attr.MTimeSeconds)
				utimes[1].Nsec = int64(attr.MTimeNanoSeconds)
			} else {
				utimes[1].Nsec = unix.UTIME_NOW
			}
		}

		if l.fileType == unix.S_IFLNK {
			// utimensat operates different that other syscalls. To operate on a
			// symlink it *requires* AT_SYMLINK_NOFOLLOW with dirFD and a non-empty
			// name.
			parent, oErr := unix.Open(path.Dir(l.hostPath), openFlags|unix.O_PATH, 0)
			if oErr != nil {
				return extractErrno(oErr)
			}
			defer unix.Close(parent)

			if tErr := utimensat(parent, path.Base(l.hostPath), utimes, unix.AT_SYMLINK_NOFOLLOW); tErr != nil {
				log.Debugf("SetAttr utimens failed %q, err: %v", l.hostPath, tErr)
				err = extractErrno(tErr)
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
		uid := p9.NoUID
		if valid.UID {
			uid = attr.UID
		}
		gid := p9.NoGID
		if valid.GID {
			gid = attr.GID
		}
		if oErr := fchown(f.FD(), uid, gid); oErr != nil {
			log.Debugf("SetAttr fchownat failed %q, err: %v", l.hostPath, oErr)
			err = extractErrno(oErr)
		}
	}

	return err
}

func (l *localFile) GetXattr(name string, size uint64) (string, error) {
	if !l.attachPoint.conf.EnableVerityXattr {
		return "", unix.EOPNOTSUPP
	}
	if _, ok := verityXattrs[name]; !ok {
		return "", unix.EOPNOTSUPP
	}
	buffer := make([]byte, size)
	if _, err := unix.Fgetxattr(l.file.FD(), name, buffer); err != nil {
		return "", err
	}
	return string(buffer), nil
}

func (l *localFile) SetXattr(name string, value string, flags uint32) error {
	if !l.attachPoint.conf.EnableVerityXattr {
		return unix.EOPNOTSUPP
	}
	if _, ok := verityXattrs[name]; !ok {
		return unix.EOPNOTSUPP
	}
	return unix.Fsetxattr(l.file.FD(), name, []byte(value), int(flags))
}

func (*localFile) ListXattr(uint64) (map[string]struct{}, error) {
	return nil, unix.EOPNOTSUPP
}

func (*localFile) RemoveXattr(string) error {
	return unix.EOPNOTSUPP
}

// Allocate implements p9.File.
func (l *localFile) Allocate(mode p9.AllocateMode, offset, length uint64) error {
	if !l.isOpen() {
		return unix.EBADF
	}

	if err := unix.Fallocate(l.file.FD(), mode.ToLinux(), int64(offset), int64(length)); err != nil {
		return extractErrno(err)
	}
	return nil
}

// Rename implements p9.File; this should never be called.
func (*localFile) Rename(p9.File, string) error {
	panic("rename called directly")
}

// RenameAt implements p9.File.RenameAt.
func (l *localFile) RenameAt(oldName string, directory p9.File, newName string) error {
	if err := l.checkROMount(); err != nil {
		return err
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
		return 0, unix.EBADF
	}
	if !l.isOpen() {
		return 0, unix.EBADF
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
		return 0, unix.EBADF
	}
	if !l.isOpen() {
		return 0, unix.EBADF
	}

	w, err := l.file.WriteAt(p, int64(offset))
	if err != nil {
		return w, extractErrno(err)
	}
	return w, nil
}

// Symlink implements p9.File.
func (l *localFile) Symlink(target, newName string, uid p9.UID, gid p9.GID) (p9.QID, error) {
	if err := l.checkROMount(); err != nil {
		return p9.QID{}, err
	}

	if err := unix.Symlinkat(target, l.file.FD(), newName); err != nil {
		return p9.QID{}, extractErrno(err)
	}
	cu := cleanup.Make(func() {
		// Best effort attempt to remove the symlink in case of failure.
		if err := unix.Unlinkat(l.file.FD(), newName, 0); err != nil {
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

	stat, err := setOwnerIfNeeded(f.FD(), uid, gid)
	if err != nil {
		return p9.QID{}, extractErrno(err)
	}

	cu.Release()
	return l.attachPoint.makeQID(&stat), nil
}

// Link implements p9.File.
func (l *localFile) Link(target p9.File, newName string) error {
	if err := l.checkROMount(); err != nil {
		return err
	}

	targetFile := target.(*localFile)
	if err := unix.Linkat(targetFile.file.FD(), "", l.file.FD(), newName, unix.AT_EMPTY_PATH); err != nil {
		return extractErrno(err)
	}
	return nil
}

// Mknod implements p9.File.
func (l *localFile) Mknod(name string, mode p9.FileMode, _ uint32, _ uint32, uid p9.UID, gid p9.GID) (p9.QID, error) {
	if err := l.checkROMount(); err != nil {
		return p9.QID{}, err
	}

	// From mknod(2) man page:
	// "EPERM: [...] if the filesystem containing pathname does not support
	// the type of node requested."
	if mode.FileType() != p9.ModeRegular {
		return p9.QID{}, unix.EPERM
	}

	// Allow Mknod to create regular files.
	if err := unix.Mknodat(l.file.FD(), name, uint32(mode), 0); err != nil {
		return p9.QID{}, err
	}
	cu := cleanup.Make(func() {
		// Best effort attempt to remove the file in case of failure.
		if err := unix.Unlinkat(l.file.FD(), name, 0); err != nil {
			log.Warningf("error unlinking file %q after failure: %v", path.Join(l.hostPath, name), err)
		}
	})
	defer cu.Clean()

	// Open file to change ownership and stat it.
	child, err := fd.OpenAt(l.file, name, unix.O_PATH|openFlags, 0)
	if err != nil {
		return p9.QID{}, extractErrno(err)
	}
	defer child.Close()

	stat, err := setOwnerIfNeeded(child.FD(), uid, gid)
	if err != nil {
		return p9.QID{}, extractErrno(err)
	}

	cu.Release()
	return l.attachPoint.makeQID(&stat), nil
}

// UnlinkAt implements p9.File.
func (l *localFile) UnlinkAt(name string, flags uint32) error {
	if err := l.checkROMount(); err != nil {
		return err
	}

	if err := unix.Unlinkat(l.file.FD(), name, int(flags)); err != nil {
		return extractErrno(err)
	}
	return nil
}

// Readdir implements p9.File.
func (l *localFile) Readdir(offset uint64, count uint32) ([]p9.Dirent, error) {
	if l.mode != p9.ReadOnly && l.mode != p9.ReadWrite {
		return nil, unix.EBADF
	}
	if !l.isOpen() {
		return nil, unix.EBADF
	}

	// Readdirnames is a cursor over directories, so seek back to 0 to ensure it's
	// reading all directory contents. Take a lock because this operation is
	// stateful.
	l.readDirMu.Lock()
	defer l.readDirMu.Unlock()

	skip := uint64(0)

	// Check if the file is at the correct position already. If not, seek to
	// the beginning and read the entire directory again. We always seek if
	// offset is 0, since this is side-effectual (equivalent to rewinddir(3),
	// which causes the directory stream to resynchronize with the directory's
	// current contents).
	if l.lastDirentOffset != offset || offset == 0 {
		if _, err := unix.Seek(l.file.FD(), 0, 0); err != nil {
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
	var dirents []p9.Dirent

	// Limit 'count' to cap the slice size that is returned.
	const maxCount = 100000
	if count > maxCount {
		count = maxCount
	}

	// Pre-allocate buffers that will be reused to get partial results.
	direntsBuf := make([]byte, 8192)
	names := make([]string, 0, 100)

	end := offset + uint64(count)
	for offset < end {
		dirSize, err := unix.ReadDirent(f, direntsBuf)
		if err != nil {
			return dirents, err
		}
		if dirSize <= 0 {
			return dirents, nil
		}

		names := names[:0]
		_, _, names = unix.ParseDirent(direntsBuf[:dirSize], -1, names)

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
			qid := l.attachPoint.makeQID(&stat)
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
	return "", unix.ENOMEM
}

// Flush implements p9.File.
func (l *localFile) Flush() error {
	return nil
}

// Connect implements p9.File.
func (l *localFile) Connect(flags p9.ConnectFlags) (*fd.FD, error) {
	if !l.attachPoint.conf.HostUDS {
		return nil, unix.ECONNREFUSED
	}

	// TODO(gvisor.dev/issue/1003): Due to different app vs replacement
	// mappings, the app path may have fit in the sockaddr, but we can't
	// fit f.path in our sockaddr. We'd need to redirect through a shorter
	// path in order to actually connect to this socket.
	const UNIX_PATH_MAX = 108 // defined in afunix.h
	if len(l.hostPath) > UNIX_PATH_MAX {
		return nil, unix.ECONNREFUSED
	}

	var stype int
	switch flags {
	case p9.StreamSocket:
		stype = unix.SOCK_STREAM
	case p9.DgramSocket:
		stype = unix.SOCK_DGRAM
	case p9.SeqpacketSocket:
		stype = unix.SOCK_SEQPACKET
	default:
		return nil, unix.ENXIO
	}

	f, err := unix.Socket(unix.AF_UNIX, stype, 0)
	if err != nil {
		return nil, err
	}

	if err := unix.SetNonblock(f, true); err != nil {
		_ = unix.Close(f)
		return nil, err
	}

	sa := unix.SockaddrUnix{Name: l.hostPath}
	if err := unix.Connect(f, &sa); err != nil {
		_ = unix.Close(f)
		return nil, err
	}

	return fd.New(f), nil
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
	l.hostPath = join(newDir.(*localFile).hostPath, newName)
}

// extractErrno tries to determine the errno.
func extractErrno(err error) unix.Errno {
	if err == nil {
		// This should never happen. The likely result will be that
		// some user gets the frustrating "error: SUCCESS" message.
		log.Warningf("extractErrno called with nil error!")
		return 0
	}

	switch err {
	case os.ErrNotExist:
		return unix.ENOENT
	case os.ErrExist:
		return unix.EEXIST
	case os.ErrPermission:
		return unix.EACCES
	case os.ErrInvalid:
		return unix.EINVAL
	}

	// See if it's an errno or a common wrapped error.
	switch e := err.(type) {
	case unix.Errno:
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
	return unix.EIO
}

func (l *localFile) checkROMount() error {
	if conf := l.attachPoint.conf; conf.ROMount {
		return unix.EROFS
	}
	return nil
}

func (l *localFile) MultiGetAttr(names []string) ([]p9.FullStat, error) {
	stats := make([]p9.FullStat, 0, len(names))

	if len(names) > 0 && names[0] == "" {
		qid, valid, attr, err := l.GetAttr(p9.AttrMask{})
		if err != nil {
			return nil, err
		}
		stats = append(stats, p9.FullStat{
			QID:   qid,
			Valid: valid,
			Attr:  attr,
		})
		names = names[1:]
	}

	parent := l.file.FD()
	for _, name := range names {
		child, err := unix.Openat(parent, name, openFlags|unix.O_PATH, 0)
		if parent != l.file.FD() {
			// Parent is no longer needed.
			_ = unix.Close(parent)
			parent = -1
		}
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				// No pont in continuing any further.
				break
			}
			return nil, err
		}

		var stat unix.Stat_t
		if err := unix.Fstat(child, &stat); err != nil {
			_ = unix.Close(child)
			return nil, err
		}
		valid, attr := l.fillAttr(&stat)
		stats = append(stats, p9.FullStat{
			QID:   l.attachPoint.makeQID(&stat),
			Valid: valid,
			Attr:  attr,
		})
		if (stat.Mode & unix.S_IFMT) != unix.S_IFDIR {
			// Doesn't need to continue if entry is not a dir. Including symlinks
			// that cannot be followed.
			_ = unix.Close(child)
			break
		}
		parent = child
	}
	if parent != -1 && parent != l.file.FD() {
		_ = unix.Close(parent)
	}
	return stats, nil
}
