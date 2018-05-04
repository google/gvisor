// Copyright 2018 Google Inc.
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
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/fd"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/p9"
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
	}
	return "unknown"
}

// Config sets configuration options for each attach point.
type Config struct {
	// ROMount is set to true if this is a readonly mount.
	ROMount bool

	// LazyOpenForWrite makes the underlying file to be opened in RDONLY
	// mode initially and be reopened in case write access is desired.
	// This is done to workaround the behavior in 'overlay2' that
	// copies the entire file up eagerly when it's opened in write mode
	// even if the file is never actually written to.
	LazyOpenForWrite bool
}

type attachPoint struct {
	prefix string
	conf   Config
}

// NewAttachPoint creates a new attacher that gives local file
// access to all files under 'prefix'.
func NewAttachPoint(prefix string, c Config) p9.Attacher {
	return &attachPoint{prefix: prefix, conf: c}
}

// Attach implements p9.Attacher.
func (a *attachPoint) Attach(appPath string) (p9.File, error) {
	if !path.IsAbs(appPath) {
		return nil, fmt.Errorf("invalid path %q", appPath)
	}

	root := filepath.Join(a.prefix, appPath)
	f, err := os.OpenFile(root, openFlags|syscall.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %q, err: %v", root, err)
	}
	stat, err := stat(int(f.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to stat file %q, err: %v", root, err)
	}
	return newLocalFile(a.conf, f, root, stat)
}

func makeQID(stat syscall.Stat_t) p9.QID {
	return p9.QID{
		Type: p9.FileMode(stat.Mode).QIDType(),
		Path: stat.Ino,
	}
}

func isNameValid(name string) bool {
	if name == "" || name == "." || name == ".." {
		log.Warningf("Invalid name: %s", name)
		return false
	}
	if strings.IndexByte(name, '/') >= 0 {
		log.Warningf("Invalid name: %s", name)
		return false
	}
	return true
}

// localFile implements p9.File wrapping a local file. The underlying file
// is opened during Walk() and stored in 'controlFile' to be used with other
// operations. The mode in which the file is opened varies depending on the
// configuration (see below). 'controlFile' is dup'ed when Walk(nil) is called
// to clone the file.
//
// 'openedFile' is assigned when Open() is called. If requested open mode is
// a subset of controlFile's mode, it's possible to use the same file. If mode
// is not a subset, then another file is opened. Consequently, 'openedFile'
// could have a mode wider than requested and must be verified before read/write
// operations. Before the file is opened and after it's closed, 'mode' is set to
// an invalid value to prevent an unopened file from being used.
//
// localFile has 2 modes of operation based on the configuration:
//
// ** conf.lazyRWOpen == false **
// This is the preferred mode. 'controlFile' is opened in RW mode in Walk()
// and used across all functions. The file is never reopened as the mode will
// always be a super set of the requested open mode. This reduces the number of
// syscalls required per operation and makes it resilient to renames anywhere
// in the path to the file.
//
// ** conf.lazyRWOpen == true **
// This mode is used for better performance with 'overlay2' storage driver.
// overlay2 eagerly copies the entire file up when it's opened in write mode
// which makes the mode above perform badly when serveral of files are opened
// for read (esp. startup). In this mode, 'controlFile' is opened as readonly
// (or O_PATH for symlinks). Reopening the file is required if write mode
// is requested in Open().
type localFile struct {
	p9.DefaultWalkGetAttr

	// mu protects 'hostPath' when file is renamed.
	mu sync.Mutex

	// TODO: hostPath is not safe to use as path needs to be walked
	// everytime (and can change underneath us). Remove all usages.
	hostPath string

	// controlFile is opened when localFile is created and it's never nil.
	controlFile *os.File

	// openedFile is nil until localFile is opened. It may point to controlFile
	// or be a new file struct. See struct comment for more details.
	openedFile *os.File

	// mode is the mode in which the file was opened. Set to invalidMode
	// if localFile isn't opened.
	mode p9.OpenFlags

	ft fileType

	conf Config

	// readDirMu protects against concurrent Readdir calls.
	readDirMu sync.Mutex
}

func openAnyFile(parent *localFile, name string) (*os.File, string, error) {
	// Attempt to open file in the following mode in order:
	//   1. RDWR: for files with rw mounts and LazyOpenForWrite disabled
	//   2. RDONLY: for directories, ro mounts or LazyOpenForWrite enabled
	//   3. PATH: for symlinks
	modes := []int{syscall.O_RDWR, syscall.O_RDONLY, unix.O_PATH}
	symlinkIdx := len(modes) - 1

	startIdx := 0
	if parent.conf.ROMount || parent.conf.LazyOpenForWrite {
		// Skip attempt to open in RDWR based on configuration.
		startIdx = 1
	}

	var err error
	var fd int
	for i := startIdx; i < len(modes); i++ {
		fd, err = syscall.Openat(parent.controlFD(), name, openFlags|modes[i], 0)
		if err == nil {
			// openat succeeded, we're done.
			break
		}
		switch e := extractErrno(err); e {
		case syscall.ENOENT:
			// File doesn't exist, no point in retrying.
			return nil, "", e
		case syscall.ELOOP:
			if i < symlinkIdx {
				// File was opened with O_NOFOLLOW, so this error can only happen when
				// trying ot open a symlink. Jump straight to flags compatible with symlink.
				i = symlinkIdx - 1
			}
		}
		// openat failed. Try again with next mode, preserving 'err' in
		// case this was the last attempt.
		log.Debugf("Attempt %d to open file failed, mode: %#x, path: %s/%s, err: %v", i, openFlags|modes[i], parent.controlFile.Name(), name, err)
	}
	if err != nil {
		// All attempts to open file have failed, return the last error.
		log.Debugf("Failed to open file, path: %s/%s, err: %v", parent.controlFile.Name(), name, err)
		return nil, "", extractErrno(err)
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	newPath := path.Join(parent.hostPath, name)

	return os.NewFile(uintptr(fd), newPath), newPath, nil
}

func newLocalFile(conf Config, file *os.File, path string, stat syscall.Stat_t) (*localFile, error) {
	var ft fileType
	switch stat.Mode & syscall.S_IFMT {
	case syscall.S_IFREG:
		ft = regular
	case syscall.S_IFDIR:
		ft = directory
	case syscall.S_IFLNK:
		ft = symlink
	default:
		return nil, syscall.EINVAL
	}
	return &localFile{
		hostPath:    path,
		controlFile: file,
		conf:        conf,
		mode:        invalidMode,
		ft:          ft,
	}, nil
}

// newFDMaybe creates a fd.FD from a file, dup'ing the FD and setting it as
// non-blocking. If anything fails, returns nil. It's better to have a file
// without host FD, than to fail the operation.
func newFDMaybe(file *os.File) *fd.FD {
	fd, err := fd.NewFromFile(file)
	if err != nil {
		return nil
	}

	// fd is blocking; non-blocking is required.
	if err := syscall.SetNonblock(fd.FD(), true); err != nil {
		fd.Close()
		return nil
	}
	return fd
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

func (l *localFile) controlFD() int {
	return int(l.controlFile.Fd())
}

func (l *localFile) openedFD() int {
	if l.openedFile == nil {
		panic(fmt.Sprintf("trying to use an unopened file: %q", l.controlFile.Name()))
	}
	return int(l.openedFile.Fd())
}

// Open implements p9.File.
func (l *localFile) Open(mode p9.OpenFlags) (*fd.FD, p9.QID, uint32, error) {
	if l.openedFile != nil {
		panic(fmt.Sprintf("attempting to open already opened file: %q", l.controlFile.Name()))
	}

	// Check if control file can be used or if a new open must be created.
	var newFile *os.File
	if mode == p9.ReadOnly || !l.conf.LazyOpenForWrite {
		log.Debugf("Open reusing control file, mode: %v, %q", mode, l.controlFile.Name())
		newFile = l.controlFile
	} else {
		// Ideally reopen would call name_to_handle_at (with empty name) and open_by_handle_at
		// to reopen the file without using 'hostPath'. However, name_to_handle_at and
		// open_by_handle_at aren't supported by overlay2.
		log.Debugf("Open reopening file, mode: %v, %q", mode, l.controlFile.Name())
		var err error

		l.mu.Lock()
		newFile, err = os.OpenFile(l.hostPath, openFlags|mode.OSFlags(), 0)
		if err != nil {
			l.mu.Unlock()
			return nil, p9.QID{}, 0, extractErrno(err)
		}
		l.mu.Unlock()
	}

	stat, err := stat(int(newFile.Fd()))
	if err != nil {
		newFile.Close()
		return nil, p9.QID{}, 0, extractErrno(err)
	}

	var fd *fd.FD
	if stat.Mode&syscall.S_IFMT == syscall.S_IFREG {
		// Donate FD for regular files only.
		fd = newFDMaybe(newFile)
	}

	// Set fields on success
	l.openedFile = newFile
	l.mode = mode
	return fd, makeQID(stat), 0, nil
}

// Create implements p9.File.
func (l *localFile) Create(name string, mode p9.OpenFlags, perm p9.FileMode, uid p9.UID, gid p9.GID) (*fd.FD, p9.File, p9.QID, uint32, error) {
	if l.conf.ROMount {
		return nil, nil, p9.QID{}, 0, syscall.EBADF
	}
	if !isNameValid(name) {
		return nil, nil, p9.QID{}, 0, syscall.EINVAL
	}

	// Use a single file for both 'controlFile' and 'openedFile'. Mode must include read for control
	// and whichever else was requested by caller. Note that resulting file might have a wider mode
	// than needed for each particular case.
	flags := openFlags | syscall.O_CREAT | syscall.O_EXCL
	if mode == p9.WriteOnly {
		flags |= syscall.O_RDWR
	} else {
		flags |= mode.OSFlags()
	}

	fd, err := syscall.Openat(l.controlFD(), name, flags, uint32(perm.Permissions()))
	if err != nil {
		return nil, nil, p9.QID{}, 0, extractErrno(err)
	}
	if err := fchown(fd, uid, gid); err != nil {
		syscall.Close(fd)
		return nil, nil, p9.QID{}, 0, extractErrno(err)
	}
	stat, err := stat(fd)
	if err != nil {
		syscall.Close(fd)
		return nil, nil, p9.QID{}, 0, extractErrno(err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	cPath := path.Join(l.hostPath, name)
	f := os.NewFile(uintptr(fd), cPath)
	c := &localFile{
		hostPath:    cPath,
		controlFile: f,
		openedFile:  f,
		mode:        mode,
		conf:        l.conf,
	}
	return newFDMaybe(c.openedFile), c, makeQID(stat), 0, nil
}

// Mkdir implements p9.File.
func (l *localFile) Mkdir(name string, perm p9.FileMode, uid p9.UID, gid p9.GID) (p9.QID, error) {
	if l.conf.ROMount {
		return p9.QID{}, syscall.EBADF
	}

	if !isNameValid(name) {
		return p9.QID{}, syscall.EINVAL
	}

	if err := syscall.Mkdirat(l.controlFD(), name, uint32(perm.Permissions())); err != nil {
		return p9.QID{}, extractErrno(err)
	}

	// Open directory to change ownership and stat it.
	flags := syscall.O_DIRECTORY | syscall.O_RDONLY | openFlags
	fd, err := syscall.Openat(l.controlFD(), name, flags, 0)
	if err != nil {
		return p9.QID{}, extractErrno(err)
	}
	defer syscall.Close(fd)

	if err := fchown(fd, uid, gid); err != nil {
		return p9.QID{}, extractErrno(err)
	}
	stat, err := stat(fd)
	if err != nil {
		return p9.QID{}, extractErrno(err)
	}
	return makeQID(stat), nil
}

// Walk implements p9.File.
func (l *localFile) Walk(names []string) ([]p9.QID, p9.File, error) {
	// Duplicate current file if 'names' is empty.
	if len(names) == 0 {
		newFd, err := syscall.Dup(l.controlFD())
		if err != nil {
			return nil, nil, extractErrno(err)
		}
		stat, err := stat(newFd)
		if err != nil {
			syscall.Close(newFd)
			return nil, nil, extractErrno(err)
		}

		l.mu.Lock()
		defer l.mu.Unlock()

		c := &localFile{
			hostPath:    l.hostPath,
			controlFile: os.NewFile(uintptr(newFd), l.hostPath),
			mode:        invalidMode,
			conf:        l.conf,
		}
		return []p9.QID{makeQID(stat)}, c, nil
	}

	var qids []p9.QID
	last := l
	for _, name := range names {
		if !isNameValid(name) {
			return nil, nil, syscall.EINVAL
		}

		f, path, err := openAnyFile(last, name)
		if err != nil {
			return nil, nil, extractErrno(err)
		}
		stat, err := stat(int(f.Fd()))
		if err != nil {
			return nil, nil, extractErrno(err)
		}
		c, err := newLocalFile(last.conf, f, path, stat)
		if err != nil {
			return nil, nil, extractErrno(err)
		}

		qids = append(qids, makeQID(stat))
		last = c
	}
	return qids, last, nil
}

// StatFS implements p9.File.
func (l *localFile) StatFS() (p9.FSStat, error) {
	var s syscall.Statfs_t
	if err := syscall.Fstatfs(l.controlFD(), &s); err != nil {
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
	if l.openedFile == nil {
		return syscall.EBADF
	}
	if err := l.openedFile.Sync(); err != nil {
		return extractErrno(err)
	}
	return nil
}

// GetAttr implements p9.File.
func (l *localFile) GetAttr(_ p9.AttrMask) (p9.QID, p9.AttrMask, p9.Attr, error) {
	stat, err := stat(l.controlFD())
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

	return makeQID(stat), valid, attr, nil
}

// SetAttr implements p9.File. Due to mismatch in file API, options
// cannot be changed atomicaly and user may see partial changes when
// an error happens.
func (l *localFile) SetAttr(valid p9.SetAttrMask, attr p9.SetAttr) error {
	if l.conf.ROMount {
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
		log.Warningf("SetAttr() failed for %q, mask: %v", l.controlFile.Name(), valid)
		return syscall.EPERM
	}

	fd := l.controlFD()
	if l.conf.LazyOpenForWrite && l.ft == regular {
		// Regular files are opened in RO mode when lazy open is set.
		// Thus it needs to be reopened here for write.
		f, err := os.OpenFile(l.hostPath, openFlags|os.O_WRONLY, 0)
		if err != nil {
			return extractErrno(err)
		}
		defer f.Close()
		fd = int(f.Fd())
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
		if cerr := syscall.Fchmod(fd, uint32(attr.Permissions)); cerr != nil {
			log.Debugf("SetAttr fchmod failed %q, err: %v", l.hostPath, cerr)
			err = extractErrno(cerr)
		}
	}

	if valid.Size {
		if terr := syscall.Ftruncate(fd, int64(attr.Size)); terr != nil {
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
			f, err := os.OpenFile(path.Dir(l.hostPath), openFlags|unix.O_PATH, 0)
			if err != nil {
				return extractErrno(err)
			}
			defer f.Close()

			if terr := utimensat(int(f.Fd()), path.Base(l.hostPath), utimes, linux.AT_SYMLINK_NOFOLLOW); terr != nil {
				log.Debugf("SetAttr utimens failed %q, err: %v", l.hostPath, terr)
				err = extractErrno(terr)
			}
		} else {
			// Directories and regular files can operate directly on the fd
			// using empty name.
			if terr := utimensat(fd, "", utimes, 0); terr != nil {
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
		if oerr := syscall.Fchownat(fd, "", uid, gid, linux.AT_EMPTY_PATH|linux.AT_SYMLINK_NOFOLLOW); oerr != nil {
			log.Debugf("SetAttr fchownat failed %q, err: %v", l.hostPath, oerr)
			err = extractErrno(oerr)
		}
	}

	return err
}

// Remove implements p9.File.
//
// This is deprecated in favor of UnlinkAt.
func (*localFile) Remove() error {
	return syscall.ENOSYS
}

// Rename implements p9.File.
func (l *localFile) Rename(directory p9.File, name string) error {
	if l.conf.ROMount {
		return syscall.EBADF
	}
	if !isNameValid(name) {
		return syscall.EINVAL
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// TODO: change to renameat(2)
	parent := directory.(*localFile)
	newPath := path.Join(parent.hostPath, name)
	if err := os.Rename(l.hostPath, newPath); err != nil {
		return extractErrno(err)
	}

	// Update path on success.
	// TODO: this doesn't cover cases where any of the
	// parents have been renamed.
	l.hostPath = newPath
	return nil
}

// RenameAt implements p9.File.RenameAt.
//
// Code still uses [deprecated] Rename().
func (*localFile) RenameAt(_ string, _ p9.File, _ string) error {
	return syscall.ENOSYS
}

// ReadAt implements p9.File.
func (l *localFile) ReadAt(p []byte, offset uint64) (int, error) {
	if l.mode != p9.ReadOnly && l.mode != p9.ReadWrite {
		return 0, syscall.EBADF
	}
	if l.openedFile == nil {
		return 0, syscall.EBADF
	}

	r, err := l.openedFile.ReadAt(p, int64(offset))
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
	if l.openedFile == nil {
		return 0, syscall.EBADF
	}

	w, err := l.openedFile.WriteAt(p, int64(offset))
	if err != nil {
		return w, extractErrno(err)
	}
	return w, nil
}

// Symlink implements p9.File.
func (l *localFile) Symlink(target, newName string, uid p9.UID, gid p9.GID) (p9.QID, error) {
	if l.conf.ROMount {
		return p9.QID{}, syscall.EBADF
	}
	if !isNameValid(newName) {
		return p9.QID{}, syscall.EINVAL
	}

	if err := unix.Symlinkat(target, l.controlFD(), newName); err != nil {
		return p9.QID{}, extractErrno(err)
	}

	// Open symlink to change ownership and stat it.
	fd, err := syscall.Openat(l.controlFD(), newName, unix.O_PATH|openFlags, 0)
	if err != nil {
		return p9.QID{}, extractErrno(err)
	}
	defer syscall.Close(fd)

	if err := fchown(fd, uid, gid); err != nil {
		return p9.QID{}, extractErrno(err)
	}
	stat, err := stat(fd)
	if err != nil {
		return p9.QID{}, extractErrno(err)
	}
	return makeQID(stat), nil
}

// Link implements p9.File.
func (l *localFile) Link(target p9.File, newName string) error {
	if l.conf.ROMount {
		return syscall.EBADF
	}
	if !isNameValid(newName) {
		return syscall.EINVAL
	}

	targetFile := target.(*localFile)
	if err := unix.Linkat(targetFile.controlFD(), "", l.controlFD(), newName, linux.AT_EMPTY_PATH); err != nil {
		return extractErrno(err)
	}
	return nil
}

// Mknod implements p9.File.
//
// Not implemented.
func (*localFile) Mknod(_ string, _ p9.FileMode, _ uint32, _ uint32, _ p9.UID, _ p9.GID) (p9.QID, error) {
	return p9.QID{}, syscall.ENOSYS
}

// UnlinkAt implements p9.File.
func (l *localFile) UnlinkAt(name string, flags uint32) error {
	if l.conf.ROMount {
		return syscall.EBADF
	}
	if !isNameValid(name) {
		return syscall.EINVAL
	}
	if err := unix.Unlinkat(l.controlFD(), name, int(flags)); err != nil {
		return extractErrno(err)
	}
	return nil
}

// Readdir implements p9.File.
func (l *localFile) Readdir(offset uint64, count uint32) ([]p9.Dirent, error) {
	if l.mode != p9.ReadOnly && l.mode != p9.ReadWrite {
		return nil, syscall.EBADF
	}
	if l.openedFile == nil {
		return nil, syscall.EBADF
	}

	// Readdirnames is a cursor over directories, so seek back to 0 to ensure it's
	// reading all directory contents. Take a lock because this operation is stateful.
	l.readDirMu.Lock()
	if _, err := l.openedFile.Seek(0, 0); err != nil {
		l.readDirMu.Unlock()
		return nil, extractErrno(err)
	}
	names, err := l.openedFile.Readdirnames(-1)
	if err != nil {
		l.readDirMu.Unlock()
		return nil, extractErrno(err)
	}
	l.readDirMu.Unlock()

	var dirents []p9.Dirent
	for i := int(offset); i >= 0 && i < len(names); i++ {
		stat, err := statAt(l.openedFD(), names[i])
		if err != nil {
			continue
		}
		qid := makeQID(stat)
		dirents = append(dirents, p9.Dirent{
			QID:    qid,
			Type:   qid.Type,
			Name:   names[i],
			Offset: uint64(i + 1),
		})
	}
	return dirents, nil
}

// Readlink implements p9.File.
func (l *localFile) Readlink() (string, error) {
	// Shamelessly stolen from os.Readlink (added upper bound limit to buffer).
	for len := 128; len < 1024*1024; len *= 2 {
		b := make([]byte, len)
		n, err := unix.Readlinkat(l.controlFD(), "", b)
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
	return nil, syscall.ECONNREFUSED
}

// Close implements p9.File.
func (l *localFile) Close() error {
	err := l.controlFile.Close()

	// Close only once in case opened and control files point to
	// the same os.File struct.
	if l.openedFile != nil && l.openedFile != l.controlFile {
		err = l.openedFile.Close()
	}

	l.openedFile = nil
	l.controlFile = nil
	l.mode = invalidMode
	return err
}

// extractErrno tries to determine the errno.
func extractErrno(err error) syscall.Errno {
	if err == nil {
		// This should never happen. The likely result will be that
		// some user gets the frustration "error: SUCCESS" message.
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
