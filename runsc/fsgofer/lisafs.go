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

package fsgofer

import (
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	rwfd "gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

const (
	setStatSupportedMask = unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_SIZE | unix.STATX_ATIME | unix.STATX_MTIME
)

// RPC Handlers that perfrom path traversal must lock the server's rename mutex
// for reading to ensure that the file is not moved maliciously during
// traversal to incorrectly give access to files outside the mountpoint.
// Handlers that modify the filesystem tree must also lock the rename mutex for
// reading.
//
// Only the handlers performing rename operations must lock the server's rename
// mutex for writing.

// LisafsHandlers are fsgofer's RPC handlers for lisafs protocol messages.
// Note that FFlush, FListXattr and FRemoveXattr handlers are nil because those
// RPCs are not supported.
var LisafsHandlers = [...]lisafs.RPCHandler{
	lisafs.Channel:      lisafs.ChannelHandler,
	lisafs.Mount:        MountHandler,
	lisafs.Fstat:        StatHandler,
	lisafs.SetStat:      SetStatHandler,
	lisafs.Walk:         WalkHandler,
	lisafs.WalkStat:     WalkStatHandler,
	lisafs.OpenAt:       OpenAtHandler,
	lisafs.OpenCreateAt: OpenCreateAtHandler,
	lisafs.Close:        CloseHandler,
	lisafs.Fsync:        SyncHandler,
	lisafs.PWrite:       WriteHandler,
	lisafs.PRead:        ReadHandler,
	lisafs.MkdirAt:      MkdirAtHandler,
	lisafs.MknodAt:      MknodAtHandler,
	lisafs.SymlinkAt:    SymlinkAtHandler,
	lisafs.LinkAt:       LinkAtHandler,
	lisafs.FStatFS:      StatFSHandler,
	lisafs.FAllocate:    AllocateHandler,
	lisafs.ReadLinkAt:   ReadLinkAtHandler,
	lisafs.Connect:      ConnectHandler,
	lisafs.UnlinkAt:     UnlinkAtHandler,
	lisafs.RenameAt:     RenameAtHandler,
	lisafs.Getdents64:   Getdents64Handler,
	lisafs.FGetXattr:    GetXattrHandler,
	lisafs.FSetXattr:    SetXattrHandler,
}

// MountHandler handles the Mount RPC for fsgofer.
func MountHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.MountReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	c.AttachAt(string(req.AttachPath))
	rootFD, rootStat, err := tryOpen(c, "", nil, func(flags int) (int, error) {
		return unix.Open(c.AttachPath(), flags, 0)
	})
	if err != nil {
		return 0, nil, err
	}

	resp := &lisafs.MountResp{
		MaxM:          c.MaxMessage(),
		UnsupportedMs: c.UnsupportedMessages(),
	}
	rootFD.initInodeWithStat(&resp.Root, &rootStat)

	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// StatHandler handles the Fstat request for fsgofer.
func StatHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.StatReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	var resp lisafs.Statx
	if err := connFD.(*fdLisa).fstatTo(&resp); err != nil {
		return 0, nil, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// SetStatHandler handles the SetStat request for fsgofer.
func SetStatHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.SetStatReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	if req.Mask&^setStatSupportedMask != 0 {
		return 0, nil, unix.EPERM
	}

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*fdLisa)
	writableFD := fd.no
	if !fd.writable &&
		req.Mask&(unix.STATX_ATIME|unix.STATX_MTIME|unix.STATX_SIZE) != 0 &&
		fd.ftype == unix.S_IFREG {
		// ftruncate(2) requires the FD to be open for writing. utimensat(2)
		// requires the FD to be open for writing, see BUGS section.
		writableFD, err = unix.Openat(int(procSelfFD.FD()), strconv.Itoa(fd.no), (unix.O_WRONLY|openFlags)&^unix.O_NOFOLLOW, 0)
		if err != nil {
			return 0, nil, err
		}
		defer unix.Close(writableFD)
	}

	var resp lisafs.SetStatResp
	if req.Mask&unix.STATX_MODE != 0 {
		if err := unix.Fchmod(fd.no, req.Mode&07777); err != nil {
			log.Debugf("SetStat fchmod failed %q, err: %v", fd.hostPath(c), err)
			resp.FailureMask |= unix.STATX_MODE
		}
	}

	if req.Mask&unix.STATX_SIZE != 0 {
		if err := unix.Ftruncate(writableFD, int64(req.Size)); err != nil {
			log.Debugf("SetStat ftruncate failed %q, err: %v", fd.hostPath(c), err)
			resp.FailureMask |= unix.STATX_SIZE
		}
	}

	if req.Mask&(unix.STATX_ATIME|unix.STATX_MTIME) != 0 {
		utimes := [2]unix.Timespec{
			{Sec: 0, Nsec: unix.UTIME_OMIT},
			{Sec: 0, Nsec: unix.UTIME_OMIT},
		}
		if req.Mask&unix.STATX_ATIME != 0 {
			utimes[0].Sec = req.Atime.Sec
			utimes[0].Nsec = req.Atime.Nsec
		}
		if req.Mask&unix.STATX_MTIME != 0 {
			utimes[1].Sec = req.Mtime.Sec
			utimes[1].Nsec = req.Mtime.Nsec
		}

		if fd.ftype == unix.S_IFLNK {
			// utimensat operates different that other syscalls. To operate on a
			// symlink it *requires* AT_SYMLINK_NOFOLLOW with dirFD and a non-empty
			// name.
			c.WithRenameRLock(func() error {
				if err := utimensat(fd.node.parent.no, fd.node.name, utimes, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					log.Debugf("SetStat utimens failed %q, err: %v", fd.hostPathLocked(c), err)
					resp.FailureMask |= (req.Mask & (unix.STATX_ATIME | unix.STATX_MTIME))
				}
				return nil
			})
		} else {
			// Directories and regular files can operate directly on the fd
			// using empty name.
			if err := utimensat(writableFD, "", utimes, 0); err != nil {
				log.Debugf("SetStat utimens failed %q, err: %v", fd.hostPath(c), err)
				resp.FailureMask |= (req.Mask & (unix.STATX_ATIME | unix.STATX_MTIME))
			}
		}
	}

	if req.Mask&(unix.STATX_UID|unix.STATX_GID) != 0 {
		// "If the owner or group is specified as -1, then that ID is not changed"
		// - chown(2)
		uid := -1
		if req.Mask&unix.STATX_UID != 0 {
			uid = int(req.UID)
		}
		gid := -1
		if req.Mask&unix.STATX_GID != 0 {
			gid = int(req.GID)
		}
		if err := unix.Fchownat(fd.no, "", uid, gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			log.Debugf("SetStat fchown failed %q, err: %v", fd.hostPath(c), err)
			resp.FailureMask |= req.Mask & (unix.STATX_UID | unix.STATX_GID)
		}
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// WalkHandler handles Walk for fsgofer.
func WalkHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.WalkReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	dirFD := connFD.(*fdLisa)
	if !dirFD.isControlFD {
		// Walk is only allowed on control FDs.
		return 0, nil, unix.EINVAL
	}

	// We need to generate inodes for each component walked. We will manually
	// marshal the inodes into the payload buffer as they are generated to avoid
	// the slice allocation. The memory format should be lisafs.WalkResp's.
	var numInodes primitive.Uint32
	maxPayloadSize := numInodes.SizeBytes() + (len(req.Path) * (*lisafs.Inode)(nil).SizeBytes())
	if maxPayloadSize > int(^uint32(0)) {
		// Too much to walk, can't do.
		return 0, nil, unix.EIO
	}
	payloadBuf := comm.PayloadBuf(uint32(maxPayloadSize))
	payloadPos := numInodes.SizeBytes()

	if err := c.WithRenameRLock(func() error {
		curDirFD := dirFD
		cu := cleanup.Make(func() {
			// Destroy all newly created FDs until now. Walk upward from curDirFD to
			// dirFD. Do not destroy dirFD as the client still owns that.
			for curDirFD != dirFD {
				c.RemoveFD(curDirFD.id)
				curDirFD = curDirFD.node.parent
			}
		})
		defer cu.Clean()

		for _, name := range req.Path {
			if err := checkSafeName(name); err != nil {
				return err
			}

			child, childStat, err := tryOpen(c, name, curDirFD, func(flags int) (int, error) {
				return unix.Openat(curDirFD.no, name, flags, 0)
			})
			if err == unix.ENOENT {
				// No more path components exist on the filesystem.
				// Return the partial walk to the client.
				break
			}
			if err != nil {
				return err
			}

			// Write inode to payloadBuf and update state.
			var childInode lisafs.Inode
			child.initInodeWithStat(&childInode, &childStat)
			childInode.MarshalUnsafe(payloadBuf[payloadPos:])
			payloadPos += childInode.SizeBytes()
			numInodes++
			curDirFD = child

			// Symlinks are not cool. This client gets the symlink inode, but will have
			// to invoke Walk again with the resolved path.
			if child.ftype == unix.S_IFLNK {
				break
			}
		}
		cu.Release()
		return nil
	}); err != nil {
		return 0, nil, err
	}

	// lisafs.WalkResp writes the number of inodes in the beginning.
	numInodes.MarshalUnsafe(payloadBuf)
	return uint32(payloadPos), nil, nil
}

// WalkStatHandler handles WalkStat for fsgofer.
func WalkStatHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.WalkReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	// Note that this dirFD is allowed to not actually be a directory when the
	// only path component to walk is "" (self).
	dirFD := connFD.(*fdLisa)
	if !dirFD.isControlFD {
		// WalkStat is only allowed on control FDs.
		return 0, nil, unix.EINVAL
	}

	// We need to generate statx for dirFD + each component walked. We will
	// manually marshal the statx results into the payload buffer as they are
	// generated to avoid the slice allocation. The memory format should be the
	// same as lisafs.WalkStatResp's.
	var numStats primitive.Uint32
	maxPayloadSize := numStats.SizeBytes() + (len(req.Path) * (*lisafs.Statx)(nil).SizeBytes())
	if maxPayloadSize > int(^uint32(0)) {
		// Too much to walk, can't do.
		return 0, nil, unix.EIO
	}
	payloadBuf := comm.PayloadBuf(uint32(maxPayloadSize))
	payloadPos := numStats.SizeBytes()

	curDirFD := dirFD.no
	closeCurDirFD := func() {
		if curDirFD != dirFD.no {
			unix.Close(curDirFD)
		}
	}
	defer closeCurDirFD()
	if err := c.WithRenameRLock(func() error {
		var unixStat unix.Stat_t
		if len(req.Path) > 0 && len(req.Path[0]) == 0 {
			// Write stat results for dirFD if the first path component is "".
			if err := marshalStatToPayload(dirFD.no, payloadBuf, &payloadPos, &unixStat); err != nil {
				return err
			}
			req.Path = req.Path[1:]
			numStats++
		}

		for _, name := range req.Path {
			if err := checkSafeName(name); err != nil {
				return err
			}
			curFD, err := unix.Openat(curDirFD, name, unix.O_PATH|openFlags, 0)
			if err == unix.ENOENT {
				// No more path components exist on the filesystem. Return the partial
				// walk to the client.
				break
			}
			if err != nil {
				return err
			}
			closeCurDirFD()
			curDirFD = curFD

			// Write stat results for curFD.
			if err := marshalStatToPayload(curFD, payloadBuf, &payloadPos, &unixStat); err != nil {
				return err
			}
			numStats++

			// Symlinks are not cool. This client gets the symlink stat result, but
			// will have to invoke Walk again with the resolved path.
			if unixStat.Mode&unix.S_IFMT == unix.S_IFLNK {
				break
			}
		}
		return nil
	}); err != nil {
		return 0, nil, err
	}

	// lisafs.WalkStatResp writes the number of stats in the beginning.
	numStats.MarshalUnsafe(payloadBuf)
	return uint32(payloadPos), nil, nil
}

func marshalStatToPayload(fd int, payloadBuf []byte, payloadPos *int, unixStat *unix.Stat_t) error {
	if err := unix.Fstat(fd, unixStat); err != nil {
		return err
	}

	var stat lisafs.Statx
	stat.FromUnix(unixStat)
	stat.MarshalUnsafe(payloadBuf[*payloadPos:])
	*payloadPos += stat.SizeBytes()
	return nil
}

// OpenAtHandler handles OpenAt for fsgofer.
func OpenAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.OpenAtReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	// Only keep allowed open flags.
	if allowedFlags := req.Flags & (unix.O_ACCMODE | allowedOpenFlags); allowedFlags != req.Flags {
		log.Debugf("discarding open flags that are not allowed: old open flags = %d, new open flags = %d", req.Flags, allowedFlags)
		req.Flags = allowedFlags
	}
	req.Flags |= openFlags

	accessMode := req.Flags & unix.O_ACCMODE
	trunc := req.Flags&unix.O_TRUNC != 0
	if accessMode == unix.O_WRONLY || accessMode == unix.O_RDWR || trunc {
		if conf := c.Opts().(*Config); conf.ROMount {
			return 0, nil, unix.EROFS
		}
	}

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*fdLisa)
	if fd.ftype == unix.S_IFDIR {
		// Directory is not truncatable.
		if trunc {
			return 0, nil, unix.EISDIR
		}
		// Directory must be opened with O_RDONLY.
		if accessMode != unix.O_RDONLY {
			return 0, nil, unix.EISDIR
		}
	}

	var newFD *fdLisa
	if err := c.WithRenameRLock(func() error {
		newFDNo, err := unix.Openat(int(procSelfFD.FD()), strconv.Itoa(fd.no), int(req.Flags)&^unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		newFD = &fdLisa{
			no:          newFDNo,
			node:        fd.node,
			isControlFD: false,
			ftype:       fd.ftype,
			readable:    accessMode == unix.O_RDONLY || accessMode == unix.O_RDWR,
			writable:    accessMode == unix.O_WRONLY || accessMode == unix.O_RDWR,
		}
		newFD.initRefs(c)
		return nil
	}); err != nil {
		return 0, nil, err
	}

	var donatedFD []int
	if newFD.ftype == unix.S_IFREG {
		// Donate FD for regular files only. Since FD donation is a destructive
		// operation, we should duplicate the to-be-donated FD. Eat the error if
		// one occurs, it is better to have an FD without a host FD, than failing
		// the Open attempt.
		if dupFD, err := unix.Dup(newFD.no); err == nil {
			donatedFD = []int{dupFD}
		}
	}

	resp := lisafs.OpenAtResp{NewFD: newFD.id}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, donatedFD, nil
}

// OpenCreateAtHandler handles OpenCreateAt for fsgofer.
func OpenCreateAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.OpenCreateAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	// Only keep allowed open flags.
	if allowedFlags := req.Flags & (unix.O_ACCMODE | allowedOpenFlags); allowedFlags != req.Flags {
		log.Debugf("discarding open flags that are not allowed: old open flags = %d, new open flags = %d", req.Flags, allowedFlags)
		req.Flags = allowedFlags
	}
	req.Flags |= openFlags

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, nil, err
	}

	connDirFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connDirFD.DecRef(nil)

	dirFD := connDirFD.(*fdLisa)
	if dirFD.ftype != unix.S_IFDIR {
		return 0, nil, unix.EINVAL
	}
	if !dirFD.isControlFD {
		return 0, nil, unix.EINVAL
	}

	var resp lisafs.OpenCreateAtResp
	var newFD *fdLisa
	if err := c.WithRenameRLock(func() error {
		flags := unix.O_CREAT | unix.O_EXCL | unix.O_RDONLY | unix.O_NONBLOCK | openFlags
		childFDNo, err := unix.Openat(dirFD.no, name, flags, uint32(req.Mode)&07777)
		if err != nil {
			return err
		}

		childFD := &fdLisa{
			no: childFDNo,
			node: &node{
				name:   name,
				parent: dirFD,
			},
			isControlFD: true,
			ftype:       unix.S_IFREG,
			readable:    true,
		}
		childFD.initRefs(c)

		cu := cleanup.Make(func() {
			c.RemoveFD(childFD.id)
			// Best effort attempt to remove the file in case of failure.
			if err := unix.Unlinkat(dirFD.no, name, 0); err != nil {
				log.Warningf("error unlinking file %q after failure: %v", path.Join(dirFD.hostPathLocked(c), name), err)
			}
		})
		defer cu.Clean()

		// Set the owners as requested by the client.
		if err := unix.Fchownat(childFD.no, "", int(req.UID), int(req.GID), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}

		// Do not use the stat result from tryOpen because the owners might have
		// changed. initInode() will stat the FD again and use fresh results.
		if err := childFD.initInode(&resp.Child); err != nil {
			return err
		}

		// Now open an FD to the newly created file with the flags requested by the client.
		newFDNo, err := unix.Openat(int(procSelfFD.FD()), strconv.Itoa(childFD.no), int(req.Flags)&^unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		cu.Release()

		accessMode := req.Flags & unix.O_ACCMODE
		newFD = &fdLisa{
			no:          newFDNo,
			node:        childFD.node,
			isControlFD: false,
			ftype:       childFD.ftype,
			readable:    accessMode == unix.O_RDONLY || accessMode == unix.O_RDWR,
			writable:    accessMode == unix.O_WRONLY || accessMode == unix.O_RDWR,
		}
		newFD.initRefs(c)
		resp.NewFD = newFD.id
		return nil
	}); err != nil {
		return 0, nil, err
	}

	var donatedFD []int
	// Donate FD because open(O_CREAT|O_EXCL) always creates a regular file.
	// Since FD donation is a destructive operation, we should duplicate the
	// to-be-donated FD. Eat the error if one occurs, it is better to have an FD
	// without a host FD, than failing the Open attempt.
	if dupFD, err := unix.Dup(newFD.no); err == nil {
		donatedFD = []int{dupFD}
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, donatedFD, nil
}

// CloseHandler handles the Close request for fsgofer.
func CloseHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.CloseReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))
	c.RemoveFDs(req.FDs)

	// There is no response message for this.
	return 0, nil, nil
}

// SyncHandler handles the Fsync request for fsgofer.
func SyncHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.FsyncReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	// Return the first error we encounter, but sync everything we can
	// regardless.
	var retErr error
	for _, fdid := range req.FDs {
		if err := fsyncFD(c, fdid); err != nil && retErr == nil {
			retErr = err
		}
	}

	// There is no response message for this.
	return 0, nil, retErr
}

func fsyncFD(c *lisafs.Connection, id lisafs.FDID) error {
	connFD, err := c.LookupFD(id)
	if err != nil {
		log.Warningf("lisafs.Connection.LookupFD(%d): %v", id, err)
		return err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*fdLisa)
	if fd.isControlFD {
		log.Warningf("cannot fsync control FD %d", fd.id)
		return unix.EBADF
	}

	if err := unix.Fsync(fd.no); err != nil {
		log.Warningf("unix.Fsync(%d): %v", fd.no, err)
		return err
	}
	return nil
}

// WriteHandler handles PWrite for fsgofer.
func WriteHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.PWriteReq
	// Note that it is an optimized Unmarshal operation which avoids any buffer
	// allocation and copying. req.Buf just points to payload. This is safe to do
	// as the handler owns payload and req's lifetime is limited to the handler.
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*fdLisa)
	if fd.isControlFD {
		// Control FD should not be used for IO.
		return 0, nil, unix.EBADF
	}

	if !fd.writable {
		return 0, nil, unix.EBADF
	}

	rw := rwfd.NewReadWriter(fd.no)
	n, err := rw.WriteAt(req.Buf, int64(req.Offset))
	if err != nil {
		return 0, nil, err
	}

	resp := &lisafs.PWriteResp{Count: uint64(n)}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// ReadHandler handles PWrite for fsgofer.
func ReadHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.PReadReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*fdLisa)
	if fd.isControlFD {
		// Control FD should not be used for IO.
		return 0, nil, unix.EBADF
	}

	if !fd.readable {
		return 0, nil, unix.EPERM
	}

	// Beware of the marshalling gymnastics below. We manually marshal a part of
	// the response onto the payload buffer. The rest of the response is directly
	// written into via readat(2).
	var resp lisafs.PReadResp
	respMetaSize := uint32(resp.NumBytes.SizeBytes())
	maxRespLen := respMetaSize + req.Count

	// Read directly into the communicator's payload buffer to avoid allocations.
	payloadBuf := comm.PayloadBuf(maxRespLen)
	rw := rwfd.NewReadWriter(fd.no)
	n, err := rw.ReadAt(payloadBuf[respMetaSize:], int64(req.Offset))
	if err != nil {
		return 0, nil, err
	}

	// Write the response metadata onto the payload buffer. The response contents
	// already have been written immediately after it.
	resp.NumBytes = primitive.Uint32(n)
	resp.NumBytes.MarshalUnsafe(payloadBuf[:respMetaSize])
	return respMetaSize + uint32(n), nil, nil
}

// MkdirAtHandler handles MkdirAt for fsgofer.
func MkdirAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.MkdirAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, nil, err
	}

	connFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	dirFD := connFD.(*fdLisa)
	if !dirFD.isControlFD {
		// MkdirAt can only be used on control FDs.
		return 0, nil, unix.EINVAL
	}

	var resp lisafs.MkdirAtResp
	if err := c.WithRenameRLock(func() error {
		if err := unix.Mkdirat(dirFD.no, name, uint32(req.Mode)&07777); err != nil {
			return err
		}
		cu := cleanup.Make(func() {
			// Best effort attempt to remove the dir in case of failure.
			if err := unix.Unlinkat(dirFD.no, name, unix.AT_REMOVEDIR); err != nil {
				log.Warningf("error unlinking dir %q after failure: %v", path.Join(dirFD.hostPathLocked(c), name), err)
			}
		})
		defer cu.Clean()

		// Open directory to change ownership.
		childDirFd, err := unix.Openat(dirFD.no, name, unix.O_DIRECTORY|unix.O_RDONLY|openFlags, 0)
		if err != nil {
			return err
		}
		if err := unix.Fchownat(childDirFd, "", int(req.UID), int(req.GID), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			unix.Close(childDirFd)
			return err
		}

		childDir := &fdLisa{
			no: childDirFd,
			node: &node{
				name:   name,
				parent: dirFD,
			},
			isControlFD: true,
			ftype:       unix.S_IFDIR,
			readable:    true,
		}
		childDir.initRefs(c)

		if err := childDir.initInode(&resp.ChildDir); err != nil {
			c.RemoveFD(childDir.id)
			return err
		}
		cu.Release()

		return nil
	}); err != nil {
		return 0, nil, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// MknodAtHandler handles MknodAt for fsgofer.
func MknodAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.MknodAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	// From mknod(2) man page:
	// "EPERM: [...] if the filesystem containing pathname does not support
	// the type of node requested."
	if req.Mode&unix.S_IFMT != unix.S_IFREG {
		return 0, nil, unix.EPERM
	}

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, nil, err
	}

	connFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	dirFd := connFD.(*fdLisa)
	if !dirFd.isControlFD {
		// MknotAt can only be used on control FDs.
		return 0, nil, unix.EINVAL
	}

	var resp lisafs.MknodAtResp
	if err := c.WithRenameRLock(func() error {
		if err := unix.Mknodat(dirFd.no, name, uint32(req.Mode), 0); err != nil {
			return err
		}
		cu := cleanup.Make(func() {
			// Best effort attempt to remove the file in case of failure.
			if err := unix.Unlinkat(dirFd.no, name, 0); err != nil {
				log.Warningf("error unlinking file %q after failure: %v", path.Join(dirFd.hostPathLocked(c), name), err)
			}
		})
		defer cu.Clean()

		// Open file to change ownership.
		childFD, err := unix.Openat(dirFd.no, name, unix.O_PATH|openFlags, 0)
		if err != nil {
			return err
		}
		if err := unix.Fchownat(childFD, "", int(req.UID), int(req.GID), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			unix.Close(childFD)
			return err
		}

		child := &fdLisa{
			no: childFD,
			node: &node{
				name:   name,
				parent: dirFd,
			},
			isControlFD: true,
			ftype:       unix.S_IFREG,
			readable:    false,
		}
		child.initRefs(c)

		if err := child.initInode(&resp.Child); err != nil {
			c.RemoveFD(child.id)
			return err
		}
		cu.Release()
		return nil
	}); err != nil {
		return 0, nil, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// SymlinkAtHandler handles SymlinkAt for fsgofer.
func SymlinkAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.SymlinkAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, nil, err
	}

	connFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	dirFd := connFD.(*fdLisa)
	if !dirFd.isControlFD {
		// SymlinkAt can only be used on control FDs.
		return 0, nil, unix.EINVAL
	}

	var resp lisafs.SymlinkAtResp
	if err := c.WithRenameRLock(func() error {
		if err := unix.Symlinkat(string(req.Target), dirFd.no, name); err != nil {
			return err
		}
		cu := cleanup.Make(func() {
			// Best effort attempt to remove the symlink in case of failure.
			if err := unix.Unlinkat(dirFd.no, name, 0); err != nil {
				log.Warningf("error unlinking file %q after failure: %v", path.Join(dirFd.hostPathLocked(c), name), err)
			}
		})
		defer cu.Clean()

		// Open symlink to change ownership.
		symlinkFD, err := unix.Openat(dirFd.no, name, unix.O_PATH|openFlags, 0)
		if err != nil {
			return err
		}
		if err := unix.Fchownat(symlinkFD, "", int(req.UID), int(req.GID), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			unix.Close(symlinkFD)
			return err
		}

		symlink := &fdLisa{
			no: symlinkFD,
			node: &node{
				name:   name,
				parent: dirFd,
			},
			isControlFD: true,
			ftype:       unix.S_IFLNK,
			readable:    false,
		}
		symlink.initRefs(c)

		if err := symlink.initInode(&resp.Symlink); err != nil {
			c.RemoveFD(symlink.id)
			return err
		}
		cu.Release()
		return nil
	}); err != nil {
		return 0, nil, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// LinkAtHandler handles LinkAt for fsgofer.
func LinkAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.LinkAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, nil, err
	}

	connDirFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connDirFD.DecRef(nil)

	connTargetFD, err := c.LookupFD(req.Target)
	if err != nil {
		return 0, nil, err
	}
	defer connTargetFD.DecRef(nil)

	dirFd := connDirFD.(*fdLisa)
	targetFd := connTargetFD.(*fdLisa)
	if !dirFd.isControlFD || !targetFd.isControlFD {
		// LinkAt can only be used on control FDs.
		return 0, nil, unix.EINVAL
	}

	var resp lisafs.LinkAtResp
	if err := c.WithRenameRLock(func() error {
		if err := unix.Linkat(targetFd.no, "", dirFd.no, name, unix.AT_EMPTY_PATH); err != nil {
			return err
		}
		cu := cleanup.Make(func() {
			// Best effort attempt to remove the hard link in case of failure.
			if err := unix.Unlinkat(dirFd.no, name, 0); err != nil {
				log.Warningf("error unlinking file %q after failure: %v", path.Join(dirFd.hostPathLocked(c), name), err)
			}
		})
		defer cu.Clean()

		linkFD, linkStat, err := tryOpen(c, name, dirFd, func(flags int) (int, error) {
			return unix.Openat(dirFd.no, name, flags, 0)
		})
		if err != nil {
			return err
		}
		cu.Release()

		linkFD.initInodeWithStat(&resp.Link, &linkStat)
		return nil
	}); err != nil {
		return 0, nil, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// StatFSHandler handles FStatFS for fsgofer.
func StatFSHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.FStatFSReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*fdLisa)
	var s unix.Statfs_t
	if err := unix.Fstatfs(fd.no, &s); err != nil {
		return 0, nil, err
	}

	resp := lisafs.StatFS{
		Type:            uint64(s.Type),
		BlockSize:       s.Bsize,
		Blocks:          s.Blocks,
		BlocksFree:      s.Bfree,
		BlocksAvailable: s.Bavail,
		Files:           s.Files,
		FilesFree:       s.Ffree,
		NameLength:      uint64(s.Namelen),
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// AllocateHandler handles FAllocate for fsgofer.
func AllocateHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.FAllocateReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*fdLisa)
	if fd.isControlFD {
		return 0, nil, unix.EINVAL
	}

	if !fd.writable {
		return 0, nil, unix.EBADF
	}
	return 0, nil, unix.Fallocate(fd.no, req.Mode, int64(req.Offset), int64(req.Length))
}

// ReadLinkAtHandler handles ReadLinkAt for fsgofer.
func ReadLinkAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.ReadLinkAtReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*fdLisa)
	if fd.ftype != unix.S_IFLNK {
		return 0, nil, unix.EINVAL
	}

	// We will manually marshal lisafs.ReadLinkAtResp, which just contains a
	// lisafs.SizedString. Let unix.Readlinkat directly write into the payload
	// buffer and manually write the string size before it.

	// This is similar to what os.Readlink does.
	const limit = primitive.Uint32(1024 * 1024)
	for linkLen := primitive.Uint32(128); linkLen < limit; linkLen *= 2 {
		b := comm.PayloadBuf(uint32(linkLen) + uint32(linkLen.SizeBytes()))
		n, err := unix.Readlinkat(fd.no, "", b[linkLen.SizeBytes():])
		if err != nil {
			return 0, nil, err
		}
		if n < int(linkLen) {
			linkLen = primitive.Uint32(n)
			linkLen.MarshalUnsafe(b[:linkLen.SizeBytes()])
			return uint32(linkLen) + uint32(linkLen.SizeBytes()), nil, nil
		}
	}
	return 0, nil, unix.ENOMEM
}

// ConnectHandler handles Connect for fsgofer.
func ConnectHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if !c.Opts().(*Config).HostUDS {
		return 0, nil, unix.ECONNREFUSED
	}

	var req lisafs.ConnectReq
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	// Only SOCK_STREAM, SOCK_DGRAM and SOCK_SEQPACKET types are supported.
	if req.SockType != unix.SOCK_STREAM &&
		req.SockType != unix.SOCK_DGRAM &&
		req.SockType != unix.SOCK_SEQPACKET {
		return 0, nil, unix.ENXIO
	}

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*fdLisa)
	if fd.ftype != unix.S_IFSOCK {
		return 0, nil, unix.EINVAL
	}
	hostPath := fd.hostPath(c)

	// TODO(gvisor.dev/issue/1003): Due to different app vs replacement
	// mappings, the app path may have fit in the sockaddr, but we can't fit
	// hostPath in our sockaddr. We'd need to redirect through a shorter path
	// in order to actually connect to this socket.
	if len(hostPath) > 108 { // UNIX_PATH_MAX = 108 is defined in afunix.h.
		return 0, nil, unix.ECONNREFUSED
	}
	sock, err := unix.Socket(unix.AF_UNIX, int(req.SockType), 0)
	if err != nil {
		return 0, nil, err
	}
	if err := unix.SetNonblock(sock, true); err != nil {
		unix.Close(sock)
		return 0, nil, err
	}
	sa := unix.SockaddrUnix{Name: hostPath}
	if err := unix.Connect(sock, &sa); err != nil {
		unix.Close(sock)
		return 0, nil, err
	}

	return 0, []int{sock}, nil
}

// UnlinkAtHandler handles UnlinkAt for fsgofer.
func UnlinkAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.UnlinkAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, nil, err
	}

	connFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	dirFD := connFD.(*fdLisa)
	if dirFD.ftype != unix.S_IFDIR {
		return 0, nil, unix.EINVAL
	}

	if !dirFD.isControlFD {
		return 0, nil, unix.EINVAL
	}

	err = c.WithRenameRLock(func() error {
		return unix.Unlinkat(dirFD.no, name, int(req.Flags))
	})
	return 0, nil, err
}

// RenameAtHandler handles RenameAt for fsgofer.
func RenameAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.RenameAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	newName := string(req.NewName)
	if err := checkSafeName(newName); err != nil {
		return 0, nil, err
	}

	renamedConnFD, err := c.LookupFD(req.Renamed)
	if err != nil {
		return 0, nil, err
	}
	defer renamedConnFD.DecRef(nil)

	newDirConnFD, err := c.LookupFD(req.NewDir)
	if err != nil {
		return 0, nil, err
	}
	defer newDirConnFD.DecRef(nil)

	renamed := renamedConnFD.(*fdLisa)
	newDir := newDirConnFD.(*fdLisa)
	if newDir.ftype != unix.S_IFDIR {
		return 0, nil, unix.EINVAL
	}
	if renamed == newDir {
		return 0, nil, unix.EINVAL
	}
	if !renamed.isControlFD || !newDir.isControlFD {
		return 0, nil, unix.EINVAL
	}

	err = c.WithRenameLock(func() error {
		oldParent := renamed.node.parent
		if oldParent == nil {
			// renamed is root.
			return unix.EINVAL
		}

		if oldParent == newDir && newName == renamed.node.name {
			// Nothing to do.
			return nil
		}

		if err := renameat(oldParent.no, renamed.node.name, newDir.no, newName); err != nil {
			return err
		}
		// Update refs and node info now that we know the rename was successful.
		oldParent.DecRef(nil) // renamed dropped its ref.
		newDir.IncRef()       // renamed grabbed a ref.
		renamed.node.parent = newDir
		renamed.node.name = newName
		return nil
	})
	return 0, nil, err
}

// Getdents64Handler handles Getdents64 for fsgofer.
func Getdents64Handler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.Getdents64Req
	req.UnmarshalUnsafe(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	dirFD := connFD.(*fdLisa)
	// Getdents is only allowed on opened directory FDs.
	if dirFD.ftype != unix.S_IFDIR || dirFD.isControlFD {
		return 0, nil, unix.EINVAL
	}

	if !dirFD.readable {
		return 0, nil, unix.EBADF
	}

	// See if the client wants us to reset the FD offset.
	if req.Count < 0 {
		req.Count *= -1
		if _, err := unix.Seek(dirFD.no, 0, 0); err != nil {
			return 0, nil, err
		}
	}

	// We will manually marshal the response lisafs.Getdents64Resp. If its
	// memory format changes, the logic below should change too.

	// numDirents is the number of dirents marshalled into the payload.
	var numDirents primitive.Uint32
	// The payload starts with numDirents, dirents go right after that.
	// payloadBufPos represents the position at which to write the next dirent.
	payloadBufPos := uint32(numDirents.SizeBytes())
	// Request enough payloadBuf for 10 dirents, we will extend when needed.
	payloadBuf := comm.PayloadBuf(payloadBufPos + 10*unixDirentMaxSize)

	var direntsBuf [8192]byte
	count := int(req.Count)
	var bytesRead int
	for bytesRead < count {
		bufEnd := len(direntsBuf)
		if count-bytesRead < bufEnd {
			bufEnd = count - bytesRead
		}
		n, err := unix.Getdents(dirFD.no, direntsBuf[:bufEnd])
		if err != nil {
			if err == unix.EINVAL && bufEnd < 268 {
				// getdents64(2) returns EINVAL is returned when the result buffer is
				// too small. If bufEnd is smaller than the max size of unix.Dirent,
				// then just break here to return all dirents collected till now.
				break
			}
			return 0, nil, err
		}
		if n <= 0 {
			break
		}
		bytesRead += n

		var statErr error
		parseDirents(direntsBuf[:n], func(ino uint64, off int64, ftype uint8, name string) bool {
			dirent := lisafs.Dirent64{
				Ino:  primitive.Uint64(ino),
				Off:  primitive.Uint64(off),
				Type: primitive.Uint8(ftype),
				Name: lisafs.SizedString(name),
			}

			// The client also wants the device ID, which annoyingly incurs an
			// additional syscall per dirent. Live with it.
			stat, err := statAt(dirFD.no, name)
			if err != nil {
				statErr = err
				return false
			}
			dirent.Dev = primitive.Uint64(stat.Dev)

			// Paste the dirent into the payload buffer without having the dirent
			// escape. Request a larger buffer if needed.
			if int(payloadBufPos)+dirent.SizeBytes() > len(payloadBuf) {
				// Ask for 10 large dirents worth of more space.
				payloadBuf = comm.PayloadBuf(payloadBufPos + 10*unixDirentMaxSize)
			}
			dirent.MarshalBytes(payloadBuf[payloadBufPos:])
			payloadBufPos += uint32(dirent.SizeBytes())
			numDirents++
			return true
		})
		if statErr != nil {
			return 0, nil, statErr
		}
	}

	// The number of dirents goes at the beginning of the payload.
	numDirents.MarshalUnsafe(payloadBuf)
	return payloadBufPos, nil, nil
}

// GetXattrHandler handles FGetXattr for fsgofer.
func GetXattrHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if !c.Opts().(*Config).EnableVerityXattr {
		return 0, nil, unix.EOPNOTSUPP
	}

	var req lisafs.FGetXattrReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*fdLisa)

	// Note that this can be optimized further to avoid the 2 allocations below
	// at the cost of more complexity. You'd have to make unix.Fgetxattr write
	// directly into the payload buffer and manually write the string header
	// before it. I have chosen simplicity over efficiency here as this is not
	// a very frequently used RPC by applications.
	valueBuf := make([]byte, req.BufSize)
	valueLen, err := unix.Fgetxattr(fd.no, string(req.Name), valueBuf)
	if err != nil {
		return 0, nil, err
	}

	resp := &lisafs.FGetXattrResp{
		Value: lisafs.SizedString(valueBuf[:valueLen]),
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// SetXattrHandler handles FSetXattr for fsgofer.
func SetXattrHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if !c.Opts().(*Config).EnableVerityXattr {
		return 0, nil, unix.EOPNOTSUPP
	}

	var req lisafs.FSetXattrReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*fdLisa)
	return 0, nil, unix.Fsetxattr(fd.no, string(req.Name), []byte(req.Value), int(req.Flags))
}

// tryOpen tries to call open() with different modes as documented. It then
// initializes and returns the control FD.
//
// Precondition: parent.isControlFD.
func tryOpen(c *lisafs.Connection, name string, parent *fdLisa, open func(flags int) (int, error)) (*fdLisa, unix.Stat_t, error) {
	// Attempt to open file in the following in order:
	//   1. RDONLY | NONBLOCK: for all files, directories, ro mounts, FIFOs.
	//      Use non-blocking to prevent getting stuck inside open(2) for
	//      FIFOs. This option has no effect on regular files.
	//   2. PATH: for symlinks, sockets.
	options := []struct {
		flag     int
		readable bool
	}{
		{
			flag:     unix.O_RDONLY | unix.O_NONBLOCK,
			readable: true,
		},
		{
			flag:     unix.O_PATH,
			readable: false,
		},
	}

	for i, option := range options {
		fdno, err := open(option.flag | openFlags)
		if err == nil {
			var stat unix.Stat_t
			if err = unix.Fstat(fdno, &stat); err == nil {
				fd := &fdLisa{
					no: fdno,
					node: &node{
						name:   name,
						parent: parent,
					},
					isControlFD: true,
					ftype:       stat.Mode & unix.S_IFMT,
					readable:    option.readable,
				}
				fd.initRefs(c)
				return fd, stat, nil
			}
			unix.Close(fdno)
		}

		e := extractErrno(err)
		if e == unix.ENOENT {
			// File doesn't exist, no point in retrying.
			return nil, unix.Stat_t{}, e
		}
		if i < len(options)-1 {
			continue
		}
		return nil, unix.Stat_t{}, e
	}
	panic("unreachable")
}

// checkSafeName validates the name and returns nil or returns an error.
func checkSafeName(name string) error {
	if name != "" && !strings.Contains(name, "/") && name != "." && name != ".." {
		return nil
	}
	return unix.EINVAL
}
