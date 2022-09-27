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
	"math"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/p9"
)

const (
	allowedOpenFlags     = unix.O_ACCMODE | unix.O_TRUNC
	setStatSupportedMask = unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_SIZE | unix.STATX_ATIME | unix.STATX_MTIME
	// unixDirentMaxSize is the maximum size of unix.Dirent for amd64.
	unixDirentMaxSize = 280
)

// RPCHandler defines a handler that is invoked when the associated message is
// received. The handler is responsible for:
//
//   - Unmarshalling the request from the passed payload and interpreting it.
//   - Marshalling the response into the communicator's payload buffer.
//   - Return the number of payload bytes written.
//   - Donate any FDs (if needed) to comm which will in turn donate it to client.
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
	UnlinkAt:     UnlinkAtHandler,
	RenameAt:     RenameAtHandler,
	Getdents64:   Getdents64Handler,
	FGetXattr:    FGetXattrHandler,
	FSetXattr:    FSetXattrHandler,
	FListXattr:   FListXattrHandler,
	FRemoveXattr: FRemoveXattrHandler,
	Connect:      ConnectHandler,
	BindAt:       BindAtHandler,
	Listen:       ListenHandler,
	Accept:       AcceptHandler,
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
	var (
		mountPointFD   *ControlFD
		mountPointStat linux.Statx
		mountNode      = c.server.root
	)
	if err := c.server.withRenameReadLock(func() (err error) {
		// Maintain extra ref on mountNode to ensure existence during walk.
		mountNode.IncRef()
		defer func() {
			// Drop extra ref on mountNode. Wrap the defer call with a func so that
			// mountNode is evaluated on execution, not on defer itself.
			mountNode.DecRef(nil)
		}()

		// Walk to the mountpoint.
		pit := fspath.Parse(c.mountPath).Begin
		for pit.Ok() {
			curName := pit.String()
			if err := checkSafeName(curName); err != nil {
				return err
			}
			mountNode.opMu.RLock()
			if mountNode.isDeleted() {
				mountNode.opMu.RUnlock()
				return unix.ENOENT
			}
			mountNode.childrenMu.Lock()
			next := mountNode.LookupChildLocked(curName)
			if next == nil {
				next = &Node{}
				next.InitLocked(curName, mountNode)
			} else {
				next.IncRef()
			}
			mountNode.childrenMu.Unlock()
			mountNode.opMu.RUnlock()
			// next has an extra ref as needed. Drop extra ref on mountNode.
			mountNode.DecRef(nil)
			pit = pit.Next()
			mountNode = next
		}

		// Provide Mount with read concurrency guarantee.
		mountNode.opMu.RLock()
		defer mountNode.opMu.RUnlock()
		if mountNode.isDeleted() {
			return unix.ENOENT
		}
		mountPointFD, mountPointStat, err = c.ServerImpl().Mount(c, mountNode)
		return err
	}); err != nil {
		return 0, err
	}

	resp := MountResp{
		Root: Inode{
			ControlFD: mountPointFD.id,
			Stat:      mountPointStat,
		},
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
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)

	var resp linux.Statx
	switch t := fd.(type) {
	case *ControlFD:
		t.safelyRead(func() error {
			resp, err = t.impl.Stat()
			return err
		})
	case *OpenFD:
		t.controlFD.safelyRead(func() error {
			resp, err = t.impl.Stat()
			return err
		})
	default:
		panic(fmt.Sprintf("unknown fd type %T", t))
	}
	if err != nil {
		return 0, err
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// SetStatHandler handles the SetStat RPC.
func SetStatHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}

	var req SetStatReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)

	if req.Mask&^setStatSupportedMask != 0 {
		return 0, unix.EPERM
	}

	var resp SetStatResp
	if err := fd.safelyWrite(func() error {
		if fd.node.isDeleted() && !c.server.opts.SetAttrOnDeleted {
			return unix.EINVAL
		}
		failureMask, failureErr := fd.impl.SetStat(req)
		resp.FailureMask = failureMask
		if failureErr != nil {
			resp.FailureErrNo = uint32(p9.ExtractErrno(failureErr))
		}
		return nil
	}); err != nil {
		return 0, err
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// WalkHandler handles the Walk RPC.
func WalkHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req WalkReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	startDir, err := c.lookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer startDir.DecRef(nil)
	if !startDir.IsDir() {
		return 0, unix.ENOTDIR
	}

	// Manually marshal the inodes into the payload buffer during walk to avoid
	// the slice allocation. The memory format should be WalkResp's.
	var (
		numInodes primitive.Uint16
		status    = WalkSuccess
	)
	respMetaSize := status.SizeBytes() + numInodes.SizeBytes()
	maxPayloadSize := respMetaSize + (len(req.Path) * (*Inode)(nil).SizeBytes())
	if maxPayloadSize > math.MaxUint32 {
		// Too much to walk, can't do.
		return 0, unix.EIO
	}
	payloadBuf := comm.PayloadBuf(uint32(maxPayloadSize))
	payloadPos := respMetaSize
	if err := c.server.withRenameReadLock(func() error {
		curDir := startDir
		cu := cleanup.Make(func() {
			// Destroy all newly created FDs until now. Read the new FDIDs from the
			// payload buffer.
			buf := comm.PayloadBuf(uint32(maxPayloadSize))[respMetaSize:]
			var curIno Inode
			for i := 0; i < int(numInodes); i++ {
				buf = curIno.UnmarshalBytes(buf)
				c.removeControlFDLocked(curIno.ControlFD)
			}
		})
		defer cu.Clean()

		for _, name := range req.Path {
			if err := checkSafeName(name); err != nil {
				return err
			}
			// Symlinks terminate walk. This client gets the symlink inode, but will
			// have to invoke Walk again with the resolved path.
			if curDir.IsSymlink() {
				status = WalkComponentSymlink
				break
			}
			curDir.node.opMu.RLock()
			if curDir.node.isDeleted() {
				// It is not safe to walk on a deleted directory. It could have been
				// replaced with a malicious symlink.
				curDir.node.opMu.RUnlock()
				status = WalkComponentDoesNotExist
				break
			}
			child, childStat, err := curDir.impl.Walk(name)
			curDir.node.opMu.RUnlock()
			if err == unix.ENOENT {
				status = WalkComponentDoesNotExist
				break
			}
			if err != nil {
				return err
			}
			// Write inode into payload buffer.
			i := Inode{ControlFD: child.id, Stat: childStat}
			i.MarshalUnsafe(payloadBuf[payloadPos:])
			payloadPos += i.SizeBytes()
			numInodes++
			curDir = child
		}
		cu.Release()
		return nil
	}); err != nil {
		return 0, err
	}

	// WalkResp writes the walk status followed by the number of inodes in the
	// beginning.
	payloadBuf = status.MarshalUnsafe(payloadBuf)
	numInodes.MarshalUnsafe(payloadBuf)
	return uint32(payloadPos), nil
}

// WalkStatHandler handles the WalkStat RPC.
func WalkStatHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req WalkReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	startDir, err := c.lookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer startDir.DecRef(nil)

	// Note that this fd is allowed to not actually be a directory when the
	// only path component to walk is "" (self).
	if !startDir.IsDir() {
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

	// We will manually marshal the statx results into the payload buffer as they
	// are generated to avoid the slice allocation. The memory format should be
	// the same as WalkStatResp's.
	var numStats primitive.Uint16
	maxPayloadSize := numStats.SizeBytes() + (len(req.Path) * linux.SizeOfStatx)
	if maxPayloadSize > math.MaxUint32 {
		// Too much to walk, can't do.
		return 0, unix.EIO
	}
	payloadBuf := comm.PayloadBuf(uint32(maxPayloadSize))
	payloadPos := numStats.SizeBytes()

	if c.server.opts.WalkStatSupported {
		if err = startDir.safelyRead(func() error {
			return startDir.impl.WalkStat(req.Path, func(s linux.Statx) {
				s.MarshalUnsafe(payloadBuf[payloadPos:])
				payloadPos += s.SizeBytes()
				numStats++
			})
		}); err != nil {
			return 0, err
		}
		// WalkStatResp writes the number of stats in the beginning.
		numStats.MarshalUnsafe(payloadBuf)
		return uint32(payloadPos), nil
	}

	if err = c.server.withRenameReadLock(func() error {
		if len(req.Path) > 0 && len(req.Path[0]) == 0 {
			startDir.node.opMu.RLock()
			stat, err := startDir.impl.Stat()
			startDir.node.opMu.RUnlock()
			if err != nil {
				return err
			}
			stat.MarshalUnsafe(payloadBuf[payloadPos:])
			payloadPos += stat.SizeBytes()
			numStats++
			req.Path = req.Path[1:]
		}

		parent := startDir
		closeParent := func() {
			if parent != startDir {
				c.removeControlFDLocked(parent.id)
			}
		}
		defer closeParent()

		for _, name := range req.Path {
			parent.node.opMu.RLock()
			if parent.node.isDeleted() {
				// It is not safe to walk on a deleted directory. It could have been
				// replaced with a malicious symlink.
				parent.node.opMu.RUnlock()
				break
			}
			child, childStat, err := parent.impl.Walk(name)
			parent.node.opMu.RUnlock()
			if err != nil {
				if err == unix.ENOENT {
					break
				}
				return err
			}

			// Update with next generation.
			closeParent()
			parent = child

			// Write results.
			childStat.MarshalUnsafe(payloadBuf[payloadPos:])
			payloadPos += childStat.SizeBytes()
			numStats++

			// Symlinks terminate walk. This client gets the symlink stat result, but
			// will have to invoke Walk again with the resolved path.
			if childStat.Mode&unix.S_IFMT == unix.S_IFLNK {
				break
			}
		}
		return nil
	}); err != nil {
		return 0, err
	}

	// WalkStatResp writes the number of stats in the beginning.
	numStats.MarshalUnsafe(payloadBuf)
	return uint32(payloadPos), nil
}

// OpenAtHandler handles the OpenAt RPC.
func OpenAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req OpenAtReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

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

	fd, err := c.lookupControlFD(req.FD)
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

	var (
		openFD     *OpenFD
		hostOpenFD int
	)
	if err := fd.safelyRead(func() error {
		if fd.node.isDeleted() || fd.IsSymlink() {
			return unix.EINVAL
		}
		openFD, hostOpenFD, err = fd.impl.Open(req.Flags)
		return err
	}); err != nil {
		return 0, err
	}

	if hostOpenFD >= 0 {
		if err := comm.DonateFD(hostOpenFD); err != nil {
			return 0, err
		}
	}
	resp := OpenAtResp{OpenFD: openFD.id}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// OpenCreateAtHandler handles the OpenCreateAt RPC.
func OpenCreateAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req OpenCreateAtReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	// Only keep allowed open flags.
	if allowedFlags := req.Flags & allowedOpenFlags; allowedFlags != req.Flags {
		log.Debugf("discarding open flags that are not allowed: old open flags = %d, new open flags = %d", req.Flags, allowedFlags)
		req.Flags = allowedFlags
	}

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, err
	}

	fd, err := c.lookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsDir() {
		return 0, unix.ENOTDIR
	}

	var (
		childFD    *ControlFD
		childStat  linux.Statx
		openFD     *OpenFD
		hostOpenFD int
	)
	if err := fd.safelyWrite(func() error {
		if fd.node.isDeleted() {
			return unix.EINVAL
		}
		childFD, childStat, openFD, hostOpenFD, err = fd.impl.OpenCreate(req.Mode, req.UID, req.GID, name, uint32(req.Flags))
		return err
	}); err != nil {
		return 0, err
	}

	if hostOpenFD >= 0 {
		if err := comm.DonateFD(hostOpenFD); err != nil {
			return 0, err
		}
	}
	resp := OpenCreateAtResp{
		NewFD: openFD.id,
		Child: Inode{
			ControlFD: childFD.id,
			Stat:      childStat,
		},
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// CloseHandler handles the Close RPC.
func CloseHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req CloseReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}
	for _, fd := range req.FDs {
		c.removeFD(fd)
	}

	// There is no response message for this.
	return 0, nil
}

// FSyncHandler handles the FSync RPC.
func FSyncHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req FsyncReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

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
	fd, err := c.lookupOpenFD(id)
	if err != nil {
		return err
	}
	defer fd.DecRef(nil)
	return fd.controlFD.safelyRead(func() error {
		return fd.impl.Sync()
	})
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
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupOpenFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.writable {
		return 0, unix.EBADF
	}
	var count uint64
	if err := fd.controlFD.safelyWrite(func() error {
		count, err = fd.impl.Write(req.Buf, uint64(req.Offset))
		return err
	}); err != nil {
		return 0, err
	}
	resp := PWriteResp{Count: count}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// PReadHandler handles the PRead RPC.
func PReadHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req PReadReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupOpenFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.readable {
		return 0, unix.EBADF
	}

	// To save an allocation and a copy, we directly read into the payload
	// buffer. The rest of the response message is manually marshalled.
	var resp PReadResp
	respMetaSize := uint32(resp.NumBytes.SizeBytes())
	respPayloadLen := respMetaSize + req.Count
	if respPayloadLen > c.maxMessageSize {
		return 0, unix.ENOBUFS
	}
	payloadBuf := comm.PayloadBuf(respPayloadLen)
	var n uint64
	if err := fd.controlFD.safelyRead(func() error {
		n, err = fd.impl.Read(payloadBuf[respMetaSize:], req.Offset)
		return err
	}); err != nil {
		return 0, err
	}

	// Write the response metadata onto the payload buffer. The response contents
	// already have been written immediately after it.
	resp.NumBytes = primitive.Uint64(n)
	resp.NumBytes.MarshalUnsafe(payloadBuf)
	return respMetaSize + uint32(n), nil
}

// MkdirAtHandler handles the MkdirAt RPC.
func MkdirAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req MkdirAtReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, err
	}

	fd, err := c.lookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsDir() {
		return 0, unix.ENOTDIR
	}
	var (
		childDir     *ControlFD
		childDirStat linux.Statx
	)
	if err := fd.safelyWrite(func() error {
		if fd.node.isDeleted() {
			return unix.EINVAL
		}
		childDir, childDirStat, err = fd.impl.Mkdir(req.Mode, req.UID, req.GID, name)
		return err
	}); err != nil {
		return 0, err
	}

	resp := MkdirAtResp{
		ChildDir: Inode{
			ControlFD: childDir.id,
			Stat:      childDirStat,
		},
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// MknodAtHandler handles the MknodAt RPC.
func MknodAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req MknodAtReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, err
	}

	fd, err := c.lookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsDir() {
		return 0, unix.ENOTDIR
	}
	var (
		child     *ControlFD
		childStat linux.Statx
	)
	if err := fd.safelyWrite(func() error {
		if fd.node.isDeleted() {
			return unix.EINVAL
		}
		child, childStat, err = fd.impl.Mknod(req.Mode, req.UID, req.GID, name, uint32(req.Minor), uint32(req.Major))
		return err
	}); err != nil {
		return 0, err
	}
	resp := MknodAtResp{
		Child: Inode{
			ControlFD: child.id,
			Stat:      childStat,
		},
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// SymlinkAtHandler handles the SymlinkAt RPC.
func SymlinkAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req SymlinkAtReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, err
	}

	fd, err := c.lookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsDir() {
		return 0, unix.ENOTDIR
	}
	var (
		symlink     *ControlFD
		symlinkStat linux.Statx
	)
	if err := fd.safelyWrite(func() error {
		if fd.node.isDeleted() {
			return unix.EINVAL
		}
		symlink, symlinkStat, err = fd.impl.Symlink(name, string(req.Target), req.UID, req.GID)
		return err
	}); err != nil {
		return 0, err
	}
	resp := SymlinkAtResp{
		Symlink: Inode{
			ControlFD: symlink.id,
			Stat:      symlinkStat,
		},
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// LinkAtHandler handles the LinkAt RPC.
func LinkAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req LinkAtReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, err
	}

	fd, err := c.lookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsDir() {
		return 0, unix.ENOTDIR
	}

	targetFD, err := c.lookupControlFD(req.Target)
	if err != nil {
		return 0, err
	}
	if targetFD.IsDir() {
		// Can not create hard link to directory.
		return 0, unix.EPERM
	}
	var (
		link     *ControlFD
		linkStat linux.Statx
	)
	if err := fd.safelyWrite(func() error {
		if fd.node.isDeleted() {
			return unix.EINVAL
		}
		// This is a lock ordering issue. Need to provide safe read guarantee for
		// targetFD. We know targetFD is not a directory while fd is a directory.
		// So targetFD would either be a descendant of fd or exist elsewhere in the
		// tree. So locking fd first and targetFD later should not lead to cycles.
		targetFD.node.opMu.RLock()
		defer targetFD.node.opMu.RUnlock()
		if targetFD.node.isDeleted() {
			return unix.EINVAL
		}
		link, linkStat, err = targetFD.impl.Link(fd.impl, name)
		return err
	}); err != nil {
		return 0, err
	}
	resp := LinkAtResp{
		Link: Inode{
			ControlFD: link.id,
			Stat:      linkStat,
		},
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// FStatFSHandler handles the FStatFS RPC.
func FStatFSHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req FStatFSReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	var resp StatFS
	if err := fd.safelyRead(func() error {
		resp, err = fd.impl.StatFS()
		return err
	}); err != nil {
		return 0, err
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// FAllocateHandler handles the FAllocate RPC.
func FAllocateHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req FAllocateReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupOpenFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.writable {
		return 0, unix.EBADF
	}

	return 0, fd.controlFD.safelyWrite(func() error {
		if fd.controlFD.node.isDeleted() && !c.server.opts.AllocateOnDeleted {
			return unix.EINVAL
		}
		return fd.impl.Allocate(req.Mode, req.Offset, req.Length)
	})
}

// ReadLinkAtHandler handles the ReadLinkAt RPC.
func ReadLinkAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req ReadLinkAtReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsSymlink() {
		return 0, unix.EINVAL
	}

	// We will manually marshal ReadLinkAtResp, which just contains a
	// SizedString. Let Readlinkat directly write into the payload buffer and
	// manually write the string size before it.
	var (
		linkLen primitive.Uint16
		n       uint16
	)
	respMetaSize := uint32(linkLen.SizeBytes())
	if fd.safelyRead(func() error {
		if fd.node.isDeleted() {
			return unix.EINVAL
		}
		n, err = fd.impl.Readlink(func(dataLen uint32) []byte {
			return comm.PayloadBuf(dataLen + respMetaSize)[respMetaSize:]
		})
		return err
	}); err != nil {
		return 0, err
	}
	linkLen = primitive.Uint16(n)
	linkLen.MarshalUnsafe(comm.PayloadBuf(respMetaSize))
	return respMetaSize + uint32(n), nil
}

// FlushHandler handles the Flush RPC.
func FlushHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req FlushReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupOpenFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)

	return 0, fd.controlFD.safelyRead(func() error {
		return fd.impl.Flush()
	})
}

// ConnectHandler handles the Connect RPC.
func ConnectHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req ConnectReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsSocket() {
		return 0, unix.ENOTSOCK
	}
	var sock int
	if err := fd.safelyRead(func() error {
		if fd.node.isDeleted() {
			return unix.EINVAL
		}
		sock, err = fd.impl.Connect(req.SockType)
		return err
	}); err != nil {
		return 0, err
	}

	return 0, comm.DonateFD(sock)
}

// BindAtHandler handles the BindAt RPC.
func BindAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req BindAtReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, err
	}

	dir, err := c.lookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer dir.DecRef(nil)

	if !dir.IsDir() {
		return 0, unix.ENOTDIR
	}

	var (
		childFD       *ControlFD
		childStat     linux.Statx
		boundSocketFD *BoundSocketFD
		hostSocketFD  int
	)
	if err := dir.safelyWrite(func() error {
		if dir.node.isDeleted() {
			return unix.EINVAL
		}
		childFD, childStat, boundSocketFD, hostSocketFD, err = dir.impl.BindAt(name, uint32(req.SockType), req.Mode, req.UID, req.GID)
		return err
	}); err != nil {
		return 0, err
	}

	if err := comm.DonateFD(hostSocketFD); err != nil {
		return 0, err
	}

	resp := BindAtResp{
		Child: Inode{
			ControlFD: childFD.id,
			Stat:      childStat,
		},
		BoundSocketFD: boundSocketFD.id,
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// ListenHandler handles the Listen RPC.
func ListenHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req ListenReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}
	sock, err := c.lookupBoundSocketFD(req.FD)
	if err != nil {
		return 0, err
	}
	if err := sock.controlFD.safelyRead(func() error {
		if sock.controlFD.node.isDeleted() {
			return unix.EINVAL
		}
		return sock.impl.Listen(req.Backlog)
	}); err != nil {
		return 0, err
	}
	return 0, nil
}

// AcceptHandler handles the Accept RPC.
func AcceptHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req AcceptReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}
	sock, err := c.lookupBoundSocketFD(req.FD)
	if err != nil {
		return 0, err
	}
	var (
		newSock  int
		peerAddr string
	)
	if err := sock.controlFD.safelyRead(func() error {
		if sock.controlFD.node.isDeleted() {
			return unix.EINVAL
		}
		var err error
		newSock, peerAddr, err = sock.impl.Accept()
		return err
	}); err != nil {
		return 0, err
	}
	if err := comm.DonateFD(newSock); err != nil {
		return 0, err
	}
	resp := AcceptResp{
		PeerAddr: SizedString(peerAddr),
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil
}

// UnlinkAtHandler handles the UnlinkAt RPC.
func UnlinkAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req UnlinkAtReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, err
	}

	fd, err := c.lookupControlFD(req.DirFD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	if !fd.IsDir() {
		return 0, unix.ENOTDIR
	}
	return 0, fd.safelyWrite(func() error {
		if fd.node.isDeleted() {
			return unix.EINVAL
		}

		fd.node.childrenMu.Lock()
		childNode := fd.node.LookupChildLocked(name)
		fd.node.childrenMu.Unlock()
		if childNode != nil {
			// Before we do the unlink itself, we need to ensure that there
			// are no operations in flight on associated path node.
			//
			// This is another case of a lock ordering issue, but since we always
			// acquire deeper in the hierarchy, we know that we are free of cycles.
			childNode.opMu.Lock()
			defer childNode.opMu.Unlock()
		}
		if err := fd.impl.Unlink(name, uint32(req.Flags)); err != nil {
			return err
		}
		// Since fd.node.opMu is locked for writing, there will not be a concurrent
		// creation of a node at that position if childNode == nil. So only remove
		// node if one existed.
		if childNode != nil {
			fd.node.childrenMu.Lock()
			fd.node.removeChildLocked(name)
			fd.node.childrenMu.Unlock()
			childNode.markDeletedRecursive()
		}
		return nil
	})
}

// RenameAtHandler handles the RenameAt RPC.
func RenameAtHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req RenameAtReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	oldName := string(req.OldName)
	if err := checkSafeName(oldName); err != nil {
		return 0, err
	}
	newName := string(req.NewName)
	if err := checkSafeName(newName); err != nil {
		return 0, err
	}

	oldDir, err := c.lookupControlFD(req.OldDir)
	if err != nil {
		return 0, err
	}
	defer oldDir.DecRef(nil)
	newDir, err := c.lookupControlFD(req.NewDir)
	if err != nil {
		return 0, err
	}
	defer newDir.DecRef(nil)

	if !oldDir.IsDir() || !newDir.IsDir() {
		return 0, unix.ENOTDIR
	}

	// Hold RenameMu for writing during rename, this is important.
	return 0, oldDir.safelyGlobal(func() error {
		if oldDir.node.isDeleted() || newDir.node.isDeleted() {
			return unix.EINVAL
		}

		if oldDir.node == newDir.node && oldName == newName {
			// Nothing to do.
			return nil
		}

		// Attempt the actual rename.
		if err := oldDir.impl.RenameAt(oldName, newDir.impl, newName); err != nil {
			return err
		}

		// Successful, so update the node tree. Note that since we have global
		// concurrency guarantee here, the node tree can not be modified
		// concurrently in any way.

		// First see if a file was deleted by being replaced by the rename. If so,
		// detach it from node tree and mark it as deleted.
		newDir.node.childrenMu.Lock()
		replaced := newDir.node.removeChildLocked(newName)
		newDir.node.childrenMu.Unlock()
		if replaced != nil {
			replaced.opMu.Lock()
			replaced.markDeletedRecursive()
			replaced.opMu.Unlock()
		}

		// Now move the renamed node to the right position.
		oldDir.node.childrenMu.Lock()
		renamed := oldDir.node.removeChildLocked(oldName)
		oldDir.node.childrenMu.Unlock()
		if renamed != nil {
			renamed.parent.DecRef(nil)
			renamed.parent = newDir.node
			renamed.parent.IncRef()
			renamed.name = newName
			newDir.node.childrenMu.Lock()
			newDir.node.insertChildLocked(newName, renamed)
			newDir.node.childrenMu.Unlock()

			// Now update all FDs under the subtree rooted at renamed.
			notifyRenameRecursive(renamed)
		}
		return nil
	})
}

func notifyRenameRecursive(n *Node) {
	n.forEachFD(func(cfd *ControlFD) {
		cfd.impl.Renamed()
		cfd.forEachOpenFD(func(ofd *OpenFD) {
			ofd.impl.Renamed()
		})
	})

	n.forEachChild(func(child *Node) {
		notifyRenameRecursive(child)
	})
}

// Getdents64Handler handles the Getdents64 RPC.
func Getdents64Handler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req Getdents64Req
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupOpenFD(req.DirFD)
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

	// We will manually marshal the response Getdents64Resp.

	// numDirents is the number of dirents marshalled into the payload.
	var numDirents primitive.Uint16
	// The payload starts with numDirents, dirents go right after that.
	// payloadBufPos represents the position at which to write the next dirent.
	payloadBufPos := uint32(numDirents.SizeBytes())
	// Request enough payloadBuf for 10 dirents, we will extend when needed.
	// unix.Dirent is 280 bytes for amd64.
	payloadBuf := comm.PayloadBuf(payloadBufPos + 10*unixDirentMaxSize)
	if err := fd.controlFD.safelyRead(func() error {
		if fd.controlFD.node.isDeleted() {
			return unix.EINVAL
		}
		return fd.impl.Getdent64(uint32(req.Count), seek0, func(dirent Dirent64) {
			// Paste the dirent into the payload buffer without having the dirent
			// escape. Request a larger buffer if needed.
			if int(payloadBufPos)+dirent.SizeBytes() > len(payloadBuf) {
				// Ask for 10 large dirents worth of more space.
				payloadBuf = comm.PayloadBuf(payloadBufPos + 10*unixDirentMaxSize)
			}
			dirent.MarshalBytes(payloadBuf[payloadBufPos:])
			payloadBufPos += uint32(dirent.SizeBytes())
			numDirents++
		})
	}); err != nil {
		return 0, err
	}

	// The number of dirents goes at the beginning of the payload.
	numDirents.MarshalUnsafe(payloadBuf)
	return payloadBufPos, nil
}

// FGetXattrHandler handles the FGetXattr RPC.
func FGetXattrHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req FGetXattrReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)

	// Manually marshal FGetXattrResp to avoid allocations and copying.
	// FGetXattrResp simply is a wrapper around SizedString.
	var valueLen primitive.Uint16
	respMetaSize := uint32(valueLen.SizeBytes())
	var n uint16
	if err := fd.safelyRead(func() error {
		if fd.node.isDeleted() {
			return unix.EINVAL
		}
		n, err = fd.impl.GetXattr(string(req.Name), uint32(req.BufSize), func(dataLen uint32) []byte {
			return comm.PayloadBuf(dataLen + respMetaSize)[respMetaSize:]
		})
		return err
	}); err != nil {
		return 0, err
	}
	payloadBuf := comm.PayloadBuf(respMetaSize)
	valueLen = primitive.Uint16(n)
	valueLen.MarshalBytes(payloadBuf)
	return respMetaSize + uint32(n), nil
}

// FSetXattrHandler handles the FSetXattr RPC.
func FSetXattrHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req FSetXattrReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)
	return 0, fd.safelyWrite(func() error {
		if fd.node.isDeleted() {
			return unix.EINVAL
		}
		return fd.impl.SetXattr(string(req.Name), string(req.Value), uint32(req.Flags))
	})
}

// FListXattrHandler handles the FListXattr RPC.
func FListXattrHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req FListXattrReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)

	var resp FListXattrResp
	if fd.safelyRead(func() error {
		if fd.node.isDeleted() {
			return unix.EINVAL
		}
		resp.Xattrs, err = fd.impl.ListXattr(req.Size)
		return err
	}); err != nil {
		return 0, err
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil
}

// FRemoveXattrHandler handles the FRemoveXattr RPC.
func FRemoveXattrHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	if c.readonly {
		return 0, unix.EROFS
	}
	var req FRemoveXattrReq
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	fd, err := c.lookupControlFD(req.FD)
	if err != nil {
		return 0, err
	}
	defer fd.DecRef(nil)

	return 0, fd.safelyWrite(func() error {
		return fd.impl.RemoveXattr(string(req.Name))
	})
}

// checkSafeName validates the name and returns nil or returns an error.
func checkSafeName(name string) error {
	if name != "" && !strings.Contains(name, "/") && name != "." && name != ".." {
		return nil
	}
	return unix.EINVAL
}
