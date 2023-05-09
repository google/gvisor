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

package p9

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
)

// Attach attaches to a server.
//
// Note that authentication is not currently supported.
func (c *Client) Attach(name string) (File, error) {
	fid, ok := c.fidPool.Get()
	if !ok {
		return nil, ErrOutOfFIDs
	}

	rattach := Rattach{}
	if err := c.sendRecv(&Tattach{FID: FID(fid), Auth: Tauth{AttachName: name, AuthenticationFID: NoFID, UID: NoUID}}, &rattach); err != nil {
		c.fidPool.Put(fid)
		return nil, err
	}

	return c.newFile(FID(fid)), nil
}

// newFile returns a new client file.
func (c *Client) newFile(fid FID) *clientFile {
	return &clientFile{
		client: c,
		fid:    fid,
	}
}

// clientFile is provided to clients.
//
// This proxies all of the interfaces found in file.go.
type clientFile struct {
	DisallowServerCalls

	// client is the originating client.
	client *Client

	// fid is the FID for this file.
	fid FID

	// closed indicates whether this file has been closed.
	closed atomicbitops.Uint32
}

// Walk implements File.Walk.
func (c *clientFile) Walk(names []string) ([]QID, File, error) {
	if c.closed.Load() != 0 {
		return nil, nil, unix.EBADF
	}

	fid, ok := c.client.fidPool.Get()
	if !ok {
		return nil, nil, ErrOutOfFIDs
	}

	rwalk := Rwalk{}
	if err := c.client.sendRecv(&Twalk{FID: c.fid, NewFID: FID(fid), Names: names}, &rwalk); err != nil {
		c.client.fidPool.Put(fid)
		return nil, nil, err
	}

	// Return a new client file.
	return rwalk.QIDs, c.client.newFile(FID(fid)), nil
}

// WalkGetAttr implements File.WalkGetAttr.
func (c *clientFile) WalkGetAttr(components []string) ([]QID, File, AttrMask, Attr, error) {
	if c.closed.Load() != 0 {
		return nil, nil, AttrMask{}, Attr{}, unix.EBADF
	}

	if !versionSupportsTwalkgetattr(c.client.version) {
		qids, file, err := c.Walk(components)
		if err != nil {
			return nil, nil, AttrMask{}, Attr{}, err
		}
		_, valid, attr, err := file.GetAttr(AttrMaskAll())
		if err != nil {
			file.Close()
			return nil, nil, AttrMask{}, Attr{}, err
		}
		return qids, file, valid, attr, nil
	}

	fid, ok := c.client.fidPool.Get()
	if !ok {
		return nil, nil, AttrMask{}, Attr{}, ErrOutOfFIDs
	}

	rwalkgetattr := Rwalkgetattr{}
	if err := c.client.sendRecv(&Twalkgetattr{FID: c.fid, NewFID: FID(fid), Names: components}, &rwalkgetattr); err != nil {
		c.client.fidPool.Put(fid)
		return nil, nil, AttrMask{}, Attr{}, err
	}

	// Return a new client file.
	return rwalkgetattr.QIDs, c.client.newFile(FID(fid)), rwalkgetattr.Valid, rwalkgetattr.Attr, nil
}

func (c *clientFile) MultiGetAttr(names []string) ([]FullStat, error) {
	if c.closed.Load() != 0 {
		return nil, unix.EBADF
	}

	if versionSupportsTmultiGetAttr(c.client.version) {
		rmultigetattr := Rmultigetattr{}
		if err := c.client.sendRecv(&Tmultigetattr{FID: c.fid, Names: names}, &rmultigetattr); err != nil {
			return nil, err
		}
		return rmultigetattr.Stats, nil
	}

	stats := make([]FullStat, 0, len(names))
	var start File = c
	parent := start
	closeParent := func() {
		if parent != start {
			_ = parent.Close()
		}
	}
	defer closeParent()
	mask := AttrMaskAll()
	for i, name := range names {
		if len(name) == 0 && i == 0 {
			qid, valid, attr, err := parent.GetAttr(mask)
			if err != nil {
				return nil, err
			}
			stats = append(stats, FullStat{
				QID:   qid,
				Valid: valid,
				Attr:  attr,
			})
			continue
		}
		qids, child, valid, attr, err := parent.WalkGetAttr([]string{name})
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				return stats, nil
			}
			return nil, err
		}
		closeParent()
		parent = child
		stats = append(stats, FullStat{
			QID:   qids[0],
			Valid: valid,
			Attr:  attr,
		})
		if attr.Mode.FileType() != ModeDirectory {
			// Doesn't need to continue if entry is not a dir. Including symlinks
			// that cannot be followed.
			break
		}
	}
	return stats, nil
}

// StatFS implements File.StatFS.
func (c *clientFile) StatFS() (FSStat, error) {
	if c.closed.Load() != 0 {
		return FSStat{}, unix.EBADF
	}

	rstatfs := Rstatfs{}
	if err := c.client.sendRecv(&Tstatfs{FID: c.fid}, &rstatfs); err != nil {
		return FSStat{}, err
	}

	return rstatfs.FSStat, nil
}

// FSync implements File.FSync.
func (c *clientFile) FSync() error {
	if c.closed.Load() != 0 {
		return unix.EBADF
	}

	return c.client.sendRecv(&Tfsync{FID: c.fid}, &Rfsync{})
}

// GetAttr implements File.GetAttr.
func (c *clientFile) GetAttr(req AttrMask) (QID, AttrMask, Attr, error) {
	if c.closed.Load() != 0 {
		return QID{}, AttrMask{}, Attr{}, unix.EBADF
	}

	rgetattr := Rgetattr{}
	if err := c.client.sendRecv(&Tgetattr{FID: c.fid, AttrMask: req}, &rgetattr); err != nil {
		return QID{}, AttrMask{}, Attr{}, err
	}

	return rgetattr.QID, rgetattr.Valid, rgetattr.Attr, nil
}

// SetAttr implements File.SetAttr.
func (c *clientFile) SetAttr(valid SetAttrMask, attr SetAttr) error {
	if c.closed.Load() != 0 {
		return unix.EBADF
	}

	return c.client.sendRecv(&Tsetattr{FID: c.fid, Valid: valid, SetAttr: attr}, &Rsetattr{})
}

// GetXattr implements File.GetXattr.
func (c *clientFile) GetXattr(name string, size uint64) (string, error) {
	if c.closed.Load() != 0 {
		return "", unix.EBADF
	}
	if !versionSupportsGetSetXattr(c.client.version) {
		return "", unix.EOPNOTSUPP
	}

	rgetxattr := Rgetxattr{}
	if err := c.client.sendRecv(&Tgetxattr{FID: c.fid, Name: name, Size: size}, &rgetxattr); err != nil {
		return "", err
	}

	return rgetxattr.Value, nil
}

// SetXattr implements File.SetXattr.
func (c *clientFile) SetXattr(name, value string, flags uint32) error {
	if c.closed.Load() != 0 {
		return unix.EBADF
	}
	if !versionSupportsGetSetXattr(c.client.version) {
		return unix.EOPNOTSUPP
	}

	return c.client.sendRecv(&Tsetxattr{FID: c.fid, Name: name, Value: value, Flags: flags}, &Rsetxattr{})
}

// ListXattr implements File.ListXattr.
func (c *clientFile) ListXattr(size uint64) (map[string]struct{}, error) {
	if c.closed.Load() != 0 {
		return nil, unix.EBADF
	}
	if !versionSupportsListRemoveXattr(c.client.version) {
		return nil, unix.EOPNOTSUPP
	}

	rlistxattr := Rlistxattr{}
	if err := c.client.sendRecv(&Tlistxattr{FID: c.fid, Size: size}, &rlistxattr); err != nil {
		return nil, err
	}

	xattrs := make(map[string]struct{}, len(rlistxattr.Xattrs))
	for _, x := range rlistxattr.Xattrs {
		xattrs[x] = struct{}{}
	}
	return xattrs, nil
}

// RemoveXattr implements File.RemoveXattr.
func (c *clientFile) RemoveXattr(name string) error {
	if c.closed.Load() != 0 {
		return unix.EBADF
	}
	if !versionSupportsListRemoveXattr(c.client.version) {
		return unix.EOPNOTSUPP
	}

	return c.client.sendRecv(&Tremovexattr{FID: c.fid, Name: name}, &Rremovexattr{})
}

// Allocate implements File.Allocate.
func (c *clientFile) Allocate(mode AllocateMode, offset, length uint64) error {
	if c.closed.Load() != 0 {
		return unix.EBADF
	}
	if !versionSupportsTallocate(c.client.version) {
		return unix.EOPNOTSUPP
	}

	return c.client.sendRecv(&Tallocate{FID: c.fid, Mode: mode, Offset: offset, Length: length}, &Rallocate{})
}

// Remove implements File.Remove.
//
// N.B. This method is no longer part of the file interface and should be
// considered deprecated.
func (c *clientFile) Remove() error {
	// Avoid double close.
	if !c.closed.CompareAndSwap(0, 1) {
		return unix.EBADF
	}

	// Send the remove message.
	if err := c.client.sendRecv(&Tremove{FID: c.fid}, &Rremove{}); err != nil {
		return err
	}

	// "It is correct to consider remove to be a clunk with the side effect
	// of removing the file if permissions allow."
	// https://swtch.com/plan9port/man/man9/remove.html

	// Return the FID to the pool.
	c.client.fidPool.Put(uint64(c.fid))
	return nil
}

// Close implements File.Close.
func (c *clientFile) Close() error {
	// Avoid double close.
	if !c.closed.CompareAndSwap(0, 1) {
		return unix.EBADF
	}

	// Send the close message.
	if err := c.client.sendRecv(&Tclunk{FID: c.fid}, &Rclunk{}); err != nil {
		// If an error occurred, we toss away the FID. This isn't ideal,
		// but I'm not sure what else makes sense in this context.
		log.Warningf("Tclunk failed, losing FID %v: %v", c.fid, err)
		return err
	}

	// Return the FID to the pool.
	c.client.fidPool.Put(uint64(c.fid))
	return nil
}

// SetAttrClose implements File.SetAttrClose.
func (c *clientFile) SetAttrClose(valid SetAttrMask, attr SetAttr) error {
	if !versionSupportsTsetattrclunk(c.client.version) {
		setAttrErr := c.SetAttr(valid, attr)

		// Try to close file even in case of failure above. Since the state of the
		// file is unknown to the caller, it will not attempt to close the file
		// again.
		if err := c.Close(); err != nil {
			return err
		}

		return setAttrErr
	}

	// Avoid double close.
	if !c.closed.CompareAndSwap(0, 1) {
		return unix.EBADF
	}

	// Send the message.
	if err := c.client.sendRecv(&Tsetattrclunk{FID: c.fid, Valid: valid, SetAttr: attr}, &Rsetattrclunk{}); err != nil {
		// If an error occurred, we toss away the FID. This isn't ideal,
		// but I'm not sure what else makes sense in this context.
		log.Warningf("Tsetattrclunk failed, losing FID %v: %v", c.fid, err)
		return err
	}

	// Return the FID to the pool.
	c.client.fidPool.Put(uint64(c.fid))
	return nil
}

// Open implements File.Open.
func (c *clientFile) Open(flags OpenFlags) (*fd.FD, QID, uint32, error) {
	if c.closed.Load() != 0 {
		return nil, QID{}, 0, unix.EBADF
	}

	rlopen := Rlopen{}
	if err := c.client.sendRecv(&Tlopen{FID: c.fid, Flags: flags}, &rlopen); err != nil {
		return nil, QID{}, 0, err
	}

	return rlopen.File, rlopen.QID, rlopen.IoUnit, nil
}

func (c *clientFile) Bind(sockType uint32, sockName string, uid UID, gid GID) (File, QID, AttrMask, Attr, error) {
	if c.closed.Load() != 0 {
		return nil, QID{}, AttrMask{}, Attr{}, unix.EBADF
	}

	if !versionSupportsBind(c.client.version) {
		return nil, QID{}, AttrMask{}, Attr{}, unix.EOPNOTSUPP
	}

	fid, ok := c.client.fidPool.Get()
	if !ok {
		return nil, QID{}, AttrMask{}, Attr{}, ErrOutOfFIDs
	}

	tbind := Tbind{
		SockType:  sockType,
		SockName:  sockName,
		UID:       uid,
		GID:       gid,
		Directory: c.fid,
		NewFID:    FID(fid),
	}
	rbind := Rbind{}
	if err := c.client.sendRecv(&tbind, &rbind); err != nil {
		c.client.fidPool.Put(fid)
		return nil, QID{}, AttrMask{}, Attr{}, err
	}

	return c.client.newFile(FID(fid)), rbind.QID, rbind.Valid, rbind.Attr, nil
}

// Connect implements File.Connect.
func (c *clientFile) Connect(socketType SocketType) (*fd.FD, error) {
	if c.closed.Load() != 0 {
		return nil, unix.EBADF
	}

	if !VersionSupportsConnect(c.client.version) {
		return nil, unix.ECONNREFUSED
	}

	rlconnect := Rlconnect{}
	if err := c.client.sendRecv(&Tlconnect{FID: c.fid, SocketType: socketType}, &rlconnect); err != nil {
		return nil, err
	}

	return rlconnect.File, nil
}

// chunk applies fn to p in chunkSize-sized chunks until fn returns a partial result, p is
// exhausted, or an error is encountered (which may be io.EOF).
func chunk(chunkSize uint32, fn func([]byte, uint64) (int, error), p []byte, offset uint64) (int, error) {
	// Some p9.Clients depend on executing fn on zero-byte buffers. Handle this
	// as a special case (normally it is fine to short-circuit and return (0, nil)).
	if len(p) == 0 {
		return fn(p, offset)
	}

	// total is the cumulative bytes processed.
	var total int
	for {
		var n int
		var err error

		// We're done, don't bother trying to do anything more.
		if total == len(p) {
			return total, nil
		}

		// Apply fn to a chunkSize-sized (or less) chunk of p.
		if len(p) < total+int(chunkSize) {
			n, err = fn(p[total:], offset)
		} else {
			n, err = fn(p[total:total+int(chunkSize)], offset)
		}
		total += n
		offset += uint64(n)

		// Return whatever we have processed if we encounter an error. This error
		// could be io.EOF.
		if err != nil {
			return total, err
		}

		// Did we get a partial result? If so, return it immediately.
		if n < int(chunkSize) {
			return total, nil
		}

		// If we received more bytes than we ever requested, this is a problem.
		if total > len(p) {
			panic(fmt.Sprintf("bytes completed (%d)) > requested (%d)", total, len(p)))
		}
	}
}

// ReadAt proxies File.ReadAt.
func (c *clientFile) ReadAt(p []byte, offset uint64) (int, error) {
	return chunk(c.client.payloadSize, c.readAt, p, offset)
}

func (c *clientFile) readAt(p []byte, offset uint64) (int, error) {
	if c.closed.Load() != 0 {
		return 0, unix.EBADF
	}

	rread := Rread{Data: p}
	if err := c.client.sendRecv(&Tread{FID: c.fid, Offset: offset, Count: uint32(len(p))}, &rread); err != nil {
		return 0, err
	}

	// The message may have been truncated, or for some reason a new buffer
	// allocated. This isn't the common path, but we make sure that if the
	// payload has changed we copy it. See transport.go for more information.
	if len(p) > 0 && len(rread.Data) > 0 && &rread.Data[0] != &p[0] {
		copy(p, rread.Data)
	}

	// io.EOF is not an error that a p9 server can return. Use POSIX semantics to
	// return io.EOF manually: zero bytes were returned and a non-zero buffer was used.
	if len(rread.Data) == 0 && len(p) > 0 {
		return 0, io.EOF
	}

	return len(rread.Data), nil
}

// WriteAt proxies File.WriteAt.
func (c *clientFile) WriteAt(p []byte, offset uint64) (int, error) {
	return chunk(c.client.payloadSize, c.writeAt, p, offset)
}

func (c *clientFile) writeAt(p []byte, offset uint64) (int, error) {
	if c.closed.Load() != 0 {
		return 0, unix.EBADF
	}

	rwrite := Rwrite{}
	if err := c.client.sendRecv(&Twrite{FID: c.fid, Offset: offset, Data: p}, &rwrite); err != nil {
		return 0, err
	}

	return int(rwrite.Count), nil
}

// ReadWriterFile wraps a File and implements io.ReadWriter, io.ReaderAt, and io.WriterAt.
type ReadWriterFile struct {
	File   File
	Offset uint64
}

// Read implements part of the io.ReadWriter interface.
func (r *ReadWriterFile) Read(p []byte) (int, error) {
	n, err := r.File.ReadAt(p, r.Offset)
	r.Offset += uint64(n)
	if err != nil {
		return n, err
	}
	if n == 0 && len(p) > 0 {
		return n, io.EOF
	}
	return n, nil
}

// ReadAt implements the io.ReaderAt interface.
func (r *ReadWriterFile) ReadAt(p []byte, offset int64) (int, error) {
	n, err := r.File.ReadAt(p, uint64(offset))
	if err != nil {
		return 0, err
	}
	if n == 0 && len(p) > 0 {
		return n, io.EOF
	}
	return n, nil
}

// Write implements part of the io.ReadWriter interface.
//
// Note that this may return a short write with a nil error. This violates the
// contract of io.Writer, but is more consistent with gVisor's pattern of
// returning errors that correspond to Linux errnos. Since short writes without
// error are common in Linux, returning a nil error is appropriate.
func (r *ReadWriterFile) Write(p []byte) (int, error) {
	n, err := r.File.WriteAt(p, r.Offset)
	r.Offset += uint64(n)
	return n, err
}

// WriteAt implements the io.WriteAt interface.
//
// Note that this may return a short write with a nil error. This violates the
// contract of io.WriterAt. See comment on Write for justification.
func (r *ReadWriterFile) WriteAt(p []byte, offset int64) (int, error) {
	return r.File.WriteAt(p, uint64(offset))
}

// Rename implements File.Rename.
func (c *clientFile) Rename(dir File, name string) error {
	if c.closed.Load() != 0 {
		return unix.EBADF
	}

	clientDir, ok := dir.(*clientFile)
	if !ok {
		return unix.EBADF
	}

	return c.client.sendRecv(&Trename{FID: c.fid, Directory: clientDir.fid, Name: name}, &Rrename{})
}

// Create implements File.Create.
func (c *clientFile) Create(name string, openFlags OpenFlags, permissions FileMode, uid UID, gid GID) (*fd.FD, File, QID, uint32, error) {
	if c.closed.Load() != 0 {
		return nil, nil, QID{}, 0, unix.EBADF
	}

	msg := Tlcreate{
		FID:         c.fid,
		Name:        name,
		OpenFlags:   openFlags,
		Permissions: permissions,
		GID:         NoGID,
	}

	if versionSupportsTucreation(c.client.version) {
		msg.GID = gid
		rucreate := Rucreate{}
		if err := c.client.sendRecv(&Tucreate{Tlcreate: msg, UID: uid}, &rucreate); err != nil {
			return nil, nil, QID{}, 0, err
		}
		return rucreate.File, c, rucreate.QID, rucreate.IoUnit, nil
	}

	rlcreate := Rlcreate{}
	if err := c.client.sendRecv(&msg, &rlcreate); err != nil {
		return nil, nil, QID{}, 0, err
	}

	return rlcreate.File, c, rlcreate.QID, rlcreate.IoUnit, nil
}

// Mkdir implements File.Mkdir.
func (c *clientFile) Mkdir(name string, permissions FileMode, uid UID, gid GID) (QID, error) {
	if c.closed.Load() != 0 {
		return QID{}, unix.EBADF
	}

	msg := Tmkdir{
		Directory:   c.fid,
		Name:        name,
		Permissions: permissions,
		GID:         NoGID,
	}

	if versionSupportsTucreation(c.client.version) {
		msg.GID = gid
		rumkdir := Rumkdir{}
		if err := c.client.sendRecv(&Tumkdir{Tmkdir: msg, UID: uid}, &rumkdir); err != nil {
			return QID{}, err
		}
		return rumkdir.QID, nil
	}

	rmkdir := Rmkdir{}
	if err := c.client.sendRecv(&msg, &rmkdir); err != nil {
		return QID{}, err
	}

	return rmkdir.QID, nil
}

// Symlink implements File.Symlink.
func (c *clientFile) Symlink(oldname string, newname string, uid UID, gid GID) (QID, error) {
	if c.closed.Load() != 0 {
		return QID{}, unix.EBADF
	}

	msg := Tsymlink{
		Directory: c.fid,
		Name:      newname,
		Target:    oldname,
		GID:       NoGID,
	}

	if versionSupportsTucreation(c.client.version) {
		msg.GID = gid
		rusymlink := Rusymlink{}
		if err := c.client.sendRecv(&Tusymlink{Tsymlink: msg, UID: uid}, &rusymlink); err != nil {
			return QID{}, err
		}
		return rusymlink.QID, nil
	}

	rsymlink := Rsymlink{}
	if err := c.client.sendRecv(&msg, &rsymlink); err != nil {
		return QID{}, err
	}

	return rsymlink.QID, nil
}

// Link implements File.Link.
func (c *clientFile) Link(target File, newname string) error {
	if c.closed.Load() != 0 {
		return unix.EBADF
	}

	targetFile, ok := target.(*clientFile)
	if !ok {
		return unix.EBADF
	}

	return c.client.sendRecv(&Tlink{Directory: c.fid, Name: newname, Target: targetFile.fid}, &Rlink{})
}

// Mknod implements File.Mknod.
func (c *clientFile) Mknod(name string, mode FileMode, major uint32, minor uint32, uid UID, gid GID) (QID, error) {
	if c.closed.Load() != 0 {
		return QID{}, unix.EBADF
	}

	msg := Tmknod{
		Directory: c.fid,
		Name:      name,
		Mode:      mode,
		Major:     major,
		Minor:     minor,
		GID:       NoGID,
	}

	if versionSupportsTucreation(c.client.version) {
		msg.GID = gid
		rumknod := Rumknod{}
		if err := c.client.sendRecv(&Tumknod{Tmknod: msg, UID: uid}, &rumknod); err != nil {
			return QID{}, err
		}
		return rumknod.QID, nil
	}

	rmknod := Rmknod{}
	if err := c.client.sendRecv(&msg, &rmknod); err != nil {
		return QID{}, err
	}

	return rmknod.QID, nil
}

// RenameAt implements File.RenameAt.
func (c *clientFile) RenameAt(oldname string, newdir File, newname string) error {
	if c.closed.Load() != 0 {
		return unix.EBADF
	}

	clientNewDir, ok := newdir.(*clientFile)
	if !ok {
		return unix.EBADF
	}

	return c.client.sendRecv(&Trenameat{OldDirectory: c.fid, OldName: oldname, NewDirectory: clientNewDir.fid, NewName: newname}, &Rrenameat{})
}

// UnlinkAt implements File.UnlinkAt.
func (c *clientFile) UnlinkAt(name string, flags uint32) error {
	if c.closed.Load() != 0 {
		return unix.EBADF
	}

	return c.client.sendRecv(&Tunlinkat{Directory: c.fid, Name: name, Flags: flags}, &Runlinkat{})
}

// Readdir implements File.Readdir.
func (c *clientFile) Readdir(direntOffset uint64, count uint32) ([]Dirent, error) {
	if c.closed.Load() != 0 {
		return nil, unix.EBADF
	}

	rreaddir := Rreaddir{}
	if err := c.client.sendRecv(&Treaddir{Directory: c.fid, DirentOffset: direntOffset, Count: count}, &rreaddir); err != nil {
		return nil, err
	}

	return rreaddir.Entries, nil
}

// Readlink implements File.Readlink.
func (c *clientFile) Readlink() (string, error) {
	if c.closed.Load() != 0 {
		return "", unix.EBADF
	}

	rreadlink := Rreadlink{}
	if err := c.client.sendRecv(&Treadlink{FID: c.fid}, &rreadlink); err != nil {
		return "", err
	}

	return rreadlink.Target, nil
}

// Flush implements File.Flush.
func (c *clientFile) Flush() error {
	if c.closed.Load() != 0 {
		return unix.EBADF
	}

	if !VersionSupportsTflushf(c.client.version) {
		return nil
	}

	return c.client.sendRecv(&Tflushf{FID: c.fid}, &Rflushf{})
}
