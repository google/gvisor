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

package p9

import (
	"fmt"
	"io"
	"runtime"
	"sync/atomic"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/fd"
	"gvisor.googlesource.com/gvisor/pkg/log"
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
	cf := &clientFile{
		client: c,
		fid:    fid,
	}

	// Make sure the file is closed.
	runtime.SetFinalizer(cf, (*clientFile).Close)

	return cf
}

// clientFile is provided to clients.
//
// This proxies all of the interfaces found in file.go.
type clientFile struct {
	// client is the originating client.
	client *Client

	// fid is the FID for this file.
	fid FID

	// closed indicates whether this file has been closed.
	closed uint32
}

// Walk implements File.Walk.
func (c *clientFile) Walk(names []string) ([]QID, File, error) {
	if atomic.LoadUint32(&c.closed) != 0 {
		return nil, nil, syscall.EBADF
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
	if atomic.LoadUint32(&c.closed) != 0 {
		return nil, nil, AttrMask{}, Attr{}, syscall.EBADF
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

// StatFS implements File.StatFS.
func (c *clientFile) StatFS() (FSStat, error) {
	if atomic.LoadUint32(&c.closed) != 0 {
		return FSStat{}, syscall.EBADF
	}

	rstatfs := Rstatfs{}
	if err := c.client.sendRecv(&Tstatfs{FID: c.fid}, &rstatfs); err != nil {
		return FSStat{}, err
	}

	return rstatfs.FSStat, nil
}

// FSync implements File.FSync.
func (c *clientFile) FSync() error {
	if atomic.LoadUint32(&c.closed) != 0 {
		return syscall.EBADF
	}

	return c.client.sendRecv(&Tfsync{FID: c.fid}, &Rfsync{})
}

// GetAttr implements File.GetAttr.
func (c *clientFile) GetAttr(req AttrMask) (QID, AttrMask, Attr, error) {
	if atomic.LoadUint32(&c.closed) != 0 {
		return QID{}, AttrMask{}, Attr{}, syscall.EBADF
	}

	rgetattr := Rgetattr{}
	if err := c.client.sendRecv(&Tgetattr{FID: c.fid, AttrMask: req}, &rgetattr); err != nil {
		return QID{}, AttrMask{}, Attr{}, err
	}

	return rgetattr.QID, rgetattr.Valid, rgetattr.Attr, nil
}

// SetAttr implements File.SetAttr.
func (c *clientFile) SetAttr(valid SetAttrMask, attr SetAttr) error {
	if atomic.LoadUint32(&c.closed) != 0 {
		return syscall.EBADF
	}

	return c.client.sendRecv(&Tsetattr{FID: c.fid, Valid: valid, SetAttr: attr}, &Rsetattr{})
}

// Remove implements File.Remove.
func (c *clientFile) Remove() error {
	// Avoid double close.
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return syscall.EBADF
	}
	runtime.SetFinalizer(c, nil)

	// Send the remove message.
	if err := c.client.sendRecv(&Tremove{FID: c.fid}, &Rremove{}); err != nil {
		log.Warningf("Tremove failed, losing FID %v: %v", c.fid, err)
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
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return syscall.EBADF
	}
	runtime.SetFinalizer(c, nil)

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

// Open implements File.Open.
func (c *clientFile) Open(flags OpenFlags) (*fd.FD, QID, uint32, error) {
	if atomic.LoadUint32(&c.closed) != 0 {
		return nil, QID{}, 0, syscall.EBADF
	}

	rlopen := Rlopen{}
	if err := c.client.sendRecv(&Tlopen{FID: c.fid, Flags: flags}, &rlopen); err != nil {
		return nil, QID{}, 0, err
	}

	return rlopen.File, rlopen.QID, rlopen.IoUnit, nil
}

// Connect implements File.Connect.
func (c *clientFile) Connect(flags ConnectFlags) (*fd.FD, error) {
	if atomic.LoadUint32(&c.closed) != 0 {
		return nil, syscall.EBADF
	}

	if !VersionSupportsConnect(c.client.version) {
		return nil, syscall.ECONNREFUSED
	}

	rlconnect := Rlconnect{}
	if err := c.client.sendRecv(&Tlconnect{FID: c.fid, Flags: flags}, &rlconnect); err != nil {
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
	if atomic.LoadUint32(&c.closed) != 0 {
		return 0, syscall.EBADF
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
	if atomic.LoadUint32(&c.closed) != 0 {
		return 0, syscall.EBADF
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
func (r *ReadWriterFile) Write(p []byte) (int, error) {
	n, err := r.File.WriteAt(p, r.Offset)
	r.Offset += uint64(n)
	if err != nil {
		return n, err
	}
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

// WriteAt implements the io.WriteAt interface.
func (r *ReadWriterFile) WriteAt(p []byte, offset int64) (int, error) {
	n, err := r.File.WriteAt(p, uint64(offset))
	if err != nil {
		return n, err
	}
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

// Rename implements File.Rename.
func (c *clientFile) Rename(dir File, name string) error {
	if atomic.LoadUint32(&c.closed) != 0 {
		return syscall.EBADF
	}

	clientDir, ok := dir.(*clientFile)
	if !ok {
		return syscall.EBADF
	}

	return c.client.sendRecv(&Trename{FID: c.fid, Directory: clientDir.fid, Name: name}, &Rrename{})
}

// Create implements File.Create.
func (c *clientFile) Create(name string, openFlags OpenFlags, permissions FileMode, uid UID, gid GID) (*fd.FD, File, QID, uint32, error) {
	if atomic.LoadUint32(&c.closed) != 0 {
		return nil, nil, QID{}, 0, syscall.EBADF
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
	if atomic.LoadUint32(&c.closed) != 0 {
		return QID{}, syscall.EBADF
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
	if atomic.LoadUint32(&c.closed) != 0 {
		return QID{}, syscall.EBADF
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
	if atomic.LoadUint32(&c.closed) != 0 {
		return syscall.EBADF
	}

	targetFile, ok := target.(*clientFile)
	if !ok {
		return syscall.EBADF
	}

	return c.client.sendRecv(&Tlink{Directory: c.fid, Name: newname, Target: targetFile.fid}, &Rlink{})
}

// Mknod implements File.Mknod.
func (c *clientFile) Mknod(name string, permissions FileMode, major uint32, minor uint32, uid UID, gid GID) (QID, error) {
	if atomic.LoadUint32(&c.closed) != 0 {
		return QID{}, syscall.EBADF
	}

	msg := Tmknod{
		Directory:   c.fid,
		Name:        name,
		Permissions: permissions,
		Major:       major,
		Minor:       minor,
		GID:         NoGID,
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
	if atomic.LoadUint32(&c.closed) != 0 {
		return syscall.EBADF
	}

	clientNewDir, ok := newdir.(*clientFile)
	if !ok {
		return syscall.EBADF
	}

	return c.client.sendRecv(&Trenameat{OldDirectory: c.fid, OldName: oldname, NewDirectory: clientNewDir.fid, NewName: newname}, &Rrenameat{})
}

// UnlinkAt implements File.UnlinkAt.
func (c *clientFile) UnlinkAt(name string, flags uint32) error {
	if atomic.LoadUint32(&c.closed) != 0 {
		return syscall.EBADF
	}

	return c.client.sendRecv(&Tunlinkat{Directory: c.fid, Name: name, Flags: flags}, &Runlinkat{})
}

// Readdir implements File.Readdir.
func (c *clientFile) Readdir(offset uint64, count uint32) ([]Dirent, error) {
	if atomic.LoadUint32(&c.closed) != 0 {
		return nil, syscall.EBADF
	}

	rreaddir := Rreaddir{}
	if err := c.client.sendRecv(&Treaddir{Directory: c.fid, Offset: offset, Count: count}, &rreaddir); err != nil {
		return nil, err
	}

	return rreaddir.Entries, nil
}

// Readlink implements File.Readlink.
func (c *clientFile) Readlink() (string, error) {
	if atomic.LoadUint32(&c.closed) != 0 {
		return "", syscall.EBADF
	}

	rreadlink := Rreadlink{}
	if err := c.client.sendRecv(&Treadlink{FID: c.fid}, &rreadlink); err != nil {
		return "", err
	}

	return rreadlink.Target, nil
}

// Flush implements File.Flush.
func (c *clientFile) Flush() error {
	if atomic.LoadUint32(&c.closed) != 0 {
		return syscall.EBADF
	}

	if !VersionSupportsTflushf(c.client.version) {
		return nil
	}

	return c.client.sendRecv(&Tflushf{FID: c.fid}, &Rflushf{})
}

// Renamed implements File.Renamed.
func (c *clientFile) Renamed(newDir File, newName string) {}
