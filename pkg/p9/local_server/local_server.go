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

// Binary local_server provides a local 9P2000.L server for the p9 package.
//
// To use, first start the server:
//     local_server /tmp/my_bind_addr
//
// Then, connect using the Linux 9P filesystem:
//     mount -t 9p -o trans=unix /tmp/my_bind_addr /mnt
//
// This package also serves as an examplar.
package main

import (
	"os"
	"path"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/fd"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/unet"
)

// local wraps a local file.
type local struct {
	p9.DefaultWalkGetAttr

	path string
	file *os.File
}

// info constructs a QID for this file.
func (l *local) info() (p9.QID, os.FileInfo, error) {
	var (
		qid p9.QID
		fi  os.FileInfo
		err error
	)

	// Stat the file.
	if l.file != nil {
		fi, err = l.file.Stat()
	} else {
		fi, err = os.Lstat(l.path)
	}
	if err != nil {
		log.Warningf("error stating %#v: %v", l, err)
		return qid, nil, err
	}

	// Construct the QID type.
	qid.Type = p9.ModeFromOS(fi.Mode()).QIDType()

	// Save the path from the Ino.
	qid.Path = fi.Sys().(*syscall.Stat_t).Ino
	return qid, fi, nil
}

// Attach implements p9.Attacher.Attach.
func (l *local) Attach() (p9.File, error) {
	return &local{path: "/"}, nil
}

// Walk implements p9.File.Walk.
func (l *local) Walk(names []string) ([]p9.QID, p9.File, error) {
	var qids []p9.QID
	last := &local{path: l.path}
	for _, name := range names {
		c := &local{path: path.Join(last.path, name)}
		qid, _, err := c.info()
		if err != nil {
			return nil, nil, err
		}
		qids = append(qids, qid)
		last = c
	}
	return qids, last, nil
}

// StatFS implements p9.File.StatFS.
//
// Not implemented.
func (l *local) StatFS() (p9.FSStat, error) {
	return p9.FSStat{}, syscall.ENOSYS
}

// FSync implements p9.File.FSync.
func (l *local) FSync() error {
	return l.file.Sync()
}

// GetAttr implements p9.File.GetAttr.
//
// Not fully implemented.
func (l *local) GetAttr(req p9.AttrMask) (p9.QID, p9.AttrMask, p9.Attr, error) {
	qid, fi, err := l.info()
	if err != nil {
		return qid, p9.AttrMask{}, p9.Attr{}, err
	}

	stat := fi.Sys().(*syscall.Stat_t)
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

	return qid, valid, attr, nil
}

// SetAttr implements p9.File.SetAttr.
//
// Not implemented.
func (l *local) SetAttr(valid p9.SetAttrMask, attr p9.SetAttr) error {
	return syscall.ENOSYS
}

// Remove implements p9.File.Remove.
//
// Not implemented.
func (l *local) Remove() error {
	return syscall.ENOSYS
}

// Rename implements p9.File.Rename.
//
// Not implemented.
func (l *local) Rename(directory p9.File, name string) error {
	return syscall.ENOSYS
}

// Close implements p9.File.Close.
func (l *local) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Open implements p9.File.Open.
func (l *local) Open(mode p9.OpenFlags) (*fd.FD, p9.QID, uint32, error) {
	qid, _, err := l.info()
	if err != nil {
		return nil, qid, 0, err
	}

	// Do the actual open.
	f, err := os.OpenFile(l.path, int(mode), 0)
	if err != nil {
		return nil, qid, 0, err
	}
	l.file = f

	// Note: we don't send the local file for this server.
	return nil, qid, 4096, nil
}

// Read implements p9.File.Read.
func (l *local) ReadAt(p []byte, offset uint64) (int, error) {
	return l.file.ReadAt(p, int64(offset))
}

// Write implements p9.File.Write.
func (l *local) WriteAt(p []byte, offset uint64) (int, error) {
	return l.file.WriteAt(p, int64(offset))
}

// Create implements p9.File.Create.
func (l *local) Create(name string, mode p9.OpenFlags, permissions p9.FileMode, _ p9.UID, _ p9.GID) (*fd.FD, p9.File, p9.QID, uint32, error) {
	f, err := os.OpenFile(l.path, int(mode)|syscall.O_CREAT|syscall.O_EXCL, os.FileMode(permissions))
	if err != nil {
		return nil, nil, p9.QID{}, 0, err
	}

	l2 := &local{path: path.Join(l.path, name), file: f}
	qid, _, err := l2.info()
	if err != nil {
		l2.Close()
		return nil, nil, p9.QID{}, 0, err
	}

	return nil, l2, qid, 4096, nil
}

// Mkdir implements p9.File.Mkdir.
//
// Not properly implemented.
func (l *local) Mkdir(name string, permissions p9.FileMode, _ p9.UID, _ p9.GID) (p9.QID, error) {
	if err := os.Mkdir(path.Join(l.path, name), os.FileMode(permissions)); err != nil {
		return p9.QID{}, err
	}

	// Blank QID.
	return p9.QID{}, nil
}

// Symlink implements p9.File.Symlink.
//
// Not properly implemented.
func (l *local) Symlink(oldname string, newname string, _ p9.UID, _ p9.GID) (p9.QID, error) {
	if err := os.Symlink(oldname, path.Join(l.path, newname)); err != nil {
		return p9.QID{}, err
	}

	// Blank QID.
	return p9.QID{}, nil
}

// Link implements p9.File.Link.
//
// Not properly implemented.
func (l *local) Link(target p9.File, newname string) error {
	return os.Link(target.(*local).path, path.Join(l.path, newname))
}

// Mknod implements p9.File.Mknod.
//
// Not implemented.
func (l *local) Mknod(name string, permissions p9.FileMode, major uint32, minor uint32, _ p9.UID, _ p9.GID) (p9.QID, error) {
	return p9.QID{}, syscall.ENOSYS
}

// RenameAt implements p9.File.RenameAt.
//
// Not implemented.
func (l *local) RenameAt(oldname string, newdir p9.File, newname string) error {
	return syscall.ENOSYS
}

// UnlinkAt implements p9.File.UnlinkAt.
//
// Not implemented.
func (l *local) UnlinkAt(name string, flags uint32) error {
	return syscall.ENOSYS
}

// Readdir implements p9.File.Readdir.
func (l *local) Readdir(offset uint64, count uint32) ([]p9.Dirent, error) {
	// We only do *all* dirents in single shot.
	const maxDirentBuffer = 1024 * 1024
	buf := make([]byte, maxDirentBuffer)
	n, err := syscall.ReadDirent(int(l.file.Fd()), buf)
	if err != nil {
		// Return zero entries.
		return nil, nil
	}

	// Parse the entries; note that we read up to offset+count here.
	_, newCount, newNames := syscall.ParseDirent(buf[:n], int(offset)+int(count), nil)
	var dirents []p9.Dirent
	for i := int(offset); i >= 0 && i < newCount; i++ {
		entry := local{path: path.Join(l.path, newNames[i])}
		qid, _, err := entry.info()
		if err != nil {
			continue
		}
		dirents = append(dirents, p9.Dirent{
			QID:    qid,
			Type:   qid.Type,
			Name:   newNames[i],
			Offset: uint64(i + 1),
		})
	}

	return dirents, nil
}

// Readlink implements p9.File.Readlink.
//
// Not properly implemented.
func (l *local) Readlink() (string, error) {
	return os.Readlink(l.path)
}

// Flush implements p9.File.Flush.
func (l *local) Flush() error {
	return nil
}

// Connect implements p9.File.Connect.
func (l *local) Connect(p9.ConnectFlags) (*fd.FD, error) {
	return nil, syscall.ECONNREFUSED
}

// Renamed implements p9.File.Renamed.
func (l *local) Renamed(parent p9.File, newName string) {
	l.path = path.Join(parent.(*local).path, newName)
}

func main() {
	log.SetLevel(log.Debug)

	if len(os.Args) != 2 {
		log.Warningf("usage: %s <bind-addr>", os.Args[0])
		os.Exit(1)
	}

	// Bind and listen on the socket.
	serverSocket, err := unet.BindAndListen(os.Args[1], false)
	if err != nil {
		log.Warningf("err binding: %v", err)
		os.Exit(1)
	}

	// Run the server.
	s := p9.NewServer(&local{})
	s.Serve(serverSocket)
}

var (
	_ p9.File = &local{}
)
