// Copyright 2021 The gVisor Authors.
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

package lisafs

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

const (
	allowedOpenFlags     = unix.O_ACCMODE | unix.O_TRUNC
	setStatSupportedMask = unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_SIZE | unix.STATX_ATIME | unix.STATX_MTIME
)

// RPCHandler defines a handler that is invoked when the associated message is
// received. The handler is responsible for:
//
// * Unmarshalling the request from the passed payload and interpreting it.
// * Marshalling the response into the communicator's payload buffer.
// * Return the number of payload bytes written.
// * Donate any FDs (if needed) to comm which will in turn donate it to client.
type RPCHandler func(c *Connection, comm Communicator, payloadLen uint32) (uint32, error)

var handlers = [...]RPCHandler{
	Error:        ErrorHandler,
	Mount:        MountHandler,
	Channel:      ChannelHandler,
	FStat:        FStatHandler,
	SetStat:      SetStatHandler,
	Walk:         WalkHandler,
	WalkStat:     WalkStatHandler,
	OpenAt:       OpenAtHandler,
	OpenCreateAt: OpenCreateAtHandler,
	Close:        CloseHandler,
	FSync:        FSyncHandler,
	PWrite:       PWriteHandler,
	PRead:        PReadHandler,
	MkdirAt:      MkdirAtHandler,
	MknodAt:      MknodAtHandler,
	SymlinkAt:    SymlinkAtHandler,
	LinkAt:       LinkAtHandler,
	FStatFS:      FStatFSHandler,
	FAllocate:    FAllocateHandler,
	ReadLinkAt:   ReadLinkAtHandler,
	Flush:        FlushHandler,
	Connect:      ConnectHandler,
	UnlinkAt:     UnlinkAtHandler,
	RenameAt:     RenameAtHandler,
	Getdents64:   Getdents64Handler,
	FGetXattr:    FGetXattrHandler,
	FSetXattr:    FSetXattrHandler,
	FListXattr:   FListXattrHandler,
	FRemoveXattr: FRemoveXattrHandler,
}

// ErrorHandler handles Error message.
func ErrorHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	// Client should never send Error.
	return 0, unix.EINVAL
}

// MountHandler handles the Mount RPC. Note that there can not be concurrent
// executions of MountHandler on a connection because the connection enforces
// that Mount is the first message on the connection. Only after the connection
// has been successfully mounted can other channels be created.
func MountHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req MountReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	mountPath := path.Clean(string(req.MountPath))
	if !filepath.IsAbs(mountPath) {
		log.Warningf("mountPath %q is not absolute", mountPath)
		return 0, unix.EINVAL
	}

	if c.mounted {
		log.Warningf("connection has already been mounted at %q", mountPath)
		return 0, unix.EBUSY
	}

	rootFD, rootIno, err := c.ServerImpl().Mount(c, mountPath)
	if err != nil {
		return 0, err
	}

	c.server.addMountPoint(rootFD.FD())
	c.mounted = true
	resp := MountResp{
		Root:           rootIno,
		SupportedMs:    c.ServerImpl().SupportedMessages(),
		MaxMessageSize: primitive.Uint32(c.ServerImpl().MaxMessageSize()),
	}
	respPayloadLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respPayloadLen))
	return respPayloadLen, nil
}

// ChannelHandler handles the Channel RPC.
func ChannelHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	ch, desc, fdSock, err := c.createChannel(c.ServerImpl().MaxMessageSize())
	if err != nil {
		return 0, err
	}

	// Start servicing the channel in a separate goroutine.
	c.activeWg.Add(1)
	go func() {
		if err := c.service(ch); err != nil {
			// Don't log shutdown error which is expected during server shutdown.
			if _, ok := err.(flipcall.ShutdownError); !ok {
				log.Warningf("lisafs.Connection.service(channel = @%p): %v", ch, err)
			}
		}
		c.activeWg.Done()
	}()

	clientDataFD, err := unix.Dup(desc.FD)
	if err != nil {
		unix.Close(fdSock)
		ch.shutdown()
		return 0, err
	}

	// Respond to client with successful channel creation message.
	if err := comm.DonateFD(clientDataFD); err != nil {
		return 0, err
	}
	if err := comm.DonateFD(fdSock); err != nil {
		return 0, err
	}
	resp := ChannelResp{
		dataOffset: desc.Offset,
		dataLength: uint64(desc.Length),
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// FStatHandler handles the FStat RPC.
func FStatHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req StatReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	fd, err := c.lookupFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)

	switch t := fd.(type) {
	case *ControlFD:
		return t.impl.Stat(c, comm)
	case *OpenFD:
		return t.impl.Stat(c, comm)
	default:
		panic(fmt.Sprintf("unknown fd type %T", t))
	}
}

// SetStatHandler handles the SetStat RPC.
func SetStatHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}

	var req SetStatReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)

	if req.Mask&^setStatSupportedMask != 0 {
		return 0, unix.EPERM
	}

	return fd.impl.SetStat(c, comm, req)
}

// WalkHandler handles the Walk RPC.
func WalkHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req WalkReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsDir() {
		return 0, unix.ENOTDIR
	}
	for _, name := range req.Path {
		if err := checkSafeName(name); err != nil {
			return 0, err
		}
	}

	return fd.impl.Walk(c, comm, req.Path)
}

// WalkStatHandler handles the WalkStat RPC.
func WalkStatHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req WalkReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)

	// Note that this fd is allowed to not actually be a directory when the
	// only path component to walk is "" (self).
	if !fd.IsDir() {
		if len(req.Path) > 1 || (len(req.Path) == 1 && len(req.Path[0]) > 0) {
			return 0, unix.ENOTDIR
		}
	}
	for i, name := range req.Path {
		// First component is allowed to be "".
		if i == 0 && len(name) == 0 {
			continue
		}
		if err := checkSafeName(name); err != nil {
			return 0, err
		}
	}

	return fd.impl.WalkStat(c, comm, req.Path)
}

// OpenAtHandler handles the OpenAt RPC.
func OpenAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req OpenAtReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	// Only keep allowed open flags.
	if allowedFlags := req.Flags & allowedOpenFlags; allowedFlags != req.Flags {
		log.Debugf("discarding open flags that are not allowed: old open flags = %d, new open flags = %d", req.Flags, allowedFlags)
		req.Flags = allowedFlags
	}

	accessMode := req.Flags & unix.O_ACCMODE
	trunc := req.Flags&unix.O_TRUNC != 0
	if c.readonly && (accessMode != unix.O_RDONLY || trunc) {
		return 0, unix.EROFS
	}

	fd, err := c.LookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if fd.IsDir() {
		// Directory is not truncatable and must be opened with O_RDONLY.
		if accessMode != unix.O_RDONLY || trunc {
			return 0, unix.EISDIR
		}
	}

	return fd.impl.Open(c, comm, req.Flags)
}

// OpenCreateAtHandler handles the OpenCreateAt RPC.
func OpenCreateAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req OpenCreateAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	// Only keep allowed open flags.
	if allowedFlags := req.Flags & allowedOpenFlags; allowedFlags != req.Flags {
		log.Debugf("discarding open flags that are not allowed: old open flags = %d, new open flags = %d", req.Flags, allowedFlags)
		req.Flags = allowedFlags
	}

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, err
	}

	fd, err := c.LookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsDir() {
		return 0, unix.ENOTDIR
	}

	return fd.impl.OpenCreate(c, comm, req.Mode, req.UID, req.GID, name, uint32(req.Flags))
}

// CloseHandler handles the Close RPC.
func CloseHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req CloseReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))
	for _, fd := range req.FDs {
		c.RemoveFD(fd)
	}

	// There is no response message for this.
	return 0, nil
}

// FSyncHandler handles the FSync RPC.
func FSyncHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req FsyncReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	// Return the first error we encounter, but sync everything we can
	// regardless.
	var retErr error
	for _, fdid := range req.FDs {
		if err := c.fsyncFD(fdid); err != nil && retErr == nil {
			retErr = err
		}
	}

	// There is no response message for this.
	return 0, retErr
}

func (c *Connection) fsyncFD(id FDID) error {
	fd, err := c.LookupOpenFD(id)
	if err != nil {
		return err
	}
	return fd.impl.Sync(c)
}

// PWriteHandler handles the PWrite RPC.
func PWriteHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req PWriteReq
	// Note that it is an optimized Unmarshal operation which avoids any buffer
	// allocation and copying. req.Buf just points to payload. This is safe to do
	// as the handler owns payload and req's lifetime is limited to the handler.
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))
	fd, err := c.LookupOpenFD(req.FD)
	if err != nil {
		return 0, err
	}
	if !fd.writable {
		return 0, unix.EBADF
	}
	return fd.impl.Write(c, comm, req.Buf, uint64(req.Offset))
}

// PReadHandler handles the PRead RPC.
func PReadHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req PReadReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupOpenFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.readable {
		return 0, unix.EBADF
	}
	return fd.impl.Read(c, comm, req.Offset, req.Count)
}

// MkdirAtHandler handles the MkdirAt RPC.
func MkdirAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req MkdirAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, err
	}

	fd, err := c.LookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsDir() {
		return 0, unix.ENOTDIR
	}
	return fd.impl.Mkdir(c, comm, req.Mode, req.UID, req.GID, name)
}

// MknodAtHandler handles the MknodAt RPC.
func MknodAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req MknodAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, err
	}

	fd, err := c.LookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsDir() {
		return 0, unix.ENOTDIR
	}
	return fd.impl.Mknod(c, comm, req.Mode, req.UID, req.GID, name, uint32(req.Minor), uint32(req.Major))
}

// SymlinkAtHandler handles the SymlinkAt RPC.
func SymlinkAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req SymlinkAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, err
	}

	fd, err := c.LookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsDir() {
		return 0, unix.ENOTDIR
	}
	return fd.impl.Symlink(c, comm, name, string(req.Target), req.UID, req.GID)
}

// LinkAtHandler handles the LinkAt RPC.
func LinkAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req LinkAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, err
	}

	fd, err := c.LookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsDir() {
		return 0, unix.ENOTDIR
	}

	targetFD, err := c.LookupControlFD(req.Target)
	if err != nil {
		return 0, err
	}
	return targetFD.impl.Link(c, comm, fd.impl, name)
}

// FStatFSHandler handles the FStatFS RPC.
func FStatFSHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req FStatFSReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	return fd.impl.StatFS(c, comm)
}

// FAllocateHandler handles the FAllocate RPC.
func FAllocateHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req FAllocateReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupOpenFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.writable {
		return 0, unix.EBADF
	}
	return 0, fd.impl.Allocate(c, req.Mode, req.Offset, req.Length)
}

// ReadLinkAtHandler handles the ReadLinkAt RPC.
func ReadLinkAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req ReadLinkAtReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsSymlink() {
		return 0, unix.EINVAL
	}
	return fd.impl.Readlink(c, comm)
}

// FlushHandler handles the Flush RPC.
func FlushHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req FlushReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupOpenFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)

	return 0, fd.impl.Flush(c)
}

// ConnectHandler handles the Connect RPC.
func ConnectHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req ConnectReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsSocket() {
		return 0, unix.ENOTSOCK
	}
	return 0, fd.impl.Connect(c, comm, req.SockType)
}

// UnlinkAtHandler handles the UnlinkAt RPC.
func UnlinkAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req UnlinkAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, err
	}

	fd, err := c.LookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsDir() {
		return 0, unix.ENOTDIR
	}
	return 0, fd.impl.Unlink(c, name, uint32(req.Flags))
}

// RenameAtHandler handles the RenameAt RPC.
func RenameAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req RenameAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	newName := string(req.NewName)
	if err := checkSafeName(newName); err != nil {
		return 0, err
	}

	renamed, err := c.LookupControlFD(req.Renamed)
	if err != nil {
		return 0, err
	}
	defer renamed.DecRef(nil)

	newDir, err := c.LookupControlFD(req.NewDir)
	if err != nil {
		return 0, err
	}
	defer newDir.DecRef(nil)
	if !newDir.IsDir() {
		return 0, unix.ENOTDIR
	}

	// Hold RenameMu for writing during rename, this is important.
	c.server.RenameMu.Lock()
	defer c.server.RenameMu.Unlock()

	if renamed.parent == nil {
		// renamed is root.
		return 0, unix.EBUSY
	}

	oldParentPath := renamed.parent.FilePathLocked()
	oldPath := oldParentPath + "/" + renamed.name
	if newName == renamed.name && oldParentPath == newDir.FilePathLocked() {
		// Nothing to do.
		return 0, nil
	}

	updateControlFD, cleanUp, err := renamed.impl.RenameLocked(c, newDir.impl, newName)
	if err != nil {
		return 0, err
	}

	c.server.forEachMountPoint(func(root *ControlFD) {
		if !strings.HasPrefix(oldPath, root.name) {
			return
		}
		pit := fspath.Parse(oldPath[len(root.name):]).Begin
		root.renameRecursiveLocked(newDir, newName, pit, updateControlFD)
	})

	if cleanUp != nil {
		cleanUp()
	}
	return 0, nil
}

// Precondition: rename mutex must be locked for writing.
func (fd *ControlFD) renameRecursiveLocked(newDir *ControlFD, newName string, pit fspath.Iterator, updateControlFD func(ControlFDImpl)) {
	if !pit.Ok() {
		// fd should be renamed.
		fd.clearParentLocked()
		fd.setParentLocked(newDir)
		fd.name = newName
		if updateControlFD != nil {
			updateControlFD(fd.impl)
		}
		return
	}

	cur := pit.String()
	next := pit.Next()
	// No need to hold fd.childrenMu because RenameMu is locked for writing.
	for child := fd.children.Front(); child != nil; child = child.Next() {
		if child.name == cur {
			child.renameRecursiveLocked(newDir, newName, next, updateControlFD)
		}
	}
}

// Getdents64Handler handles the Getdents64 RPC.
func Getdents64Handler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req Getdents64Req
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupOpenFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.controlFD.IsDir() {
		return 0, unix.ENOTDIR
	}

	seek0 := false
	if req.Count < 0 {
		seek0 = true
		req.Count = -req.Count
	}
	return fd.impl.Getdent64(c, comm, uint32(req.Count), seek0)
}

// FGetXattrHandler handles the FGetXattr RPC.
func FGetXattrHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req FGetXattrReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	return fd.impl.GetXattr(c, comm, string(req.Name), uint32(req.BufSize))
}

// FSetXattrHandler handles the FSetXattr RPC.
func FSetXattrHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req FSetXattrReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	return 0, fd.impl.SetXattr(c, string(req.Name), string(req.Value), uint32(req.Flags))
}

// FListXattrHandler handles the FListXattr RPC.
func FListXattrHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req FListXattrReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	return fd.impl.ListXattr(c, comm, req.Size)
}

// FRemoveXattrHandler handles the FRemoveXattr RPC.
func FRemoveXattrHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req FRemoveXattrReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	fd, err := c.LookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	return 0, fd.impl.RemoveXattr(c, comm, string(req.Name))
}

// checkSafeName validates the name and returns nil or returns an error.
func checkSafeName(name string) error {
	if name != "" && !strings.Contains(name, "/") && name != "." && name != ".." {
		return nil
	}
	return unix.EINVAL
}
