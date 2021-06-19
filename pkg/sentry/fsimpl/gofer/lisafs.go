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

package gofer

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

const fdCacheSize int = 100

func (fs *filesystem) openAtLisa(ctx context.Context, fd lisafs.FDID, flags uint32) (lisafs.FDID, int, error) {
	req := lisafs.OpenAtReq{
		FD:    fd,
		Flags: flags,
	}
	var resp lisafs.OpenAtResp
	respFD := [1]int{-1}
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.OpenAt, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.UnmarshalUnsafe, respFD[:])
	ctx.UninterruptibleSleepFinish(false)
	return resp.NewFD, respFD[0], err
}

func (fs *filesystem) openCreateAtLisa(ctx context.Context, dirFD lisafs.FDID, name string, flags uint32, mode linux.FileMode, uid auth.KUID, gid auth.KGID) (lisafs.Inode, lisafs.FDID, int, error) {
	var req lisafs.OpenCreateAtReq
	req.DirFD = dirFD
	req.Name = lisafs.SizedString(name)
	req.Flags = primitive.Uint32(flags)
	req.Mode = primitive.Uint32(mode)
	req.UID = lisafs.UID(uid)
	req.GID = lisafs.GID(gid)

	var resp lisafs.OpenCreateAtResp
	respFD := [1]int{-1}
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.OpenCreateAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalUnsafe, respFD[:])
	ctx.UninterruptibleSleepFinish(false)
	return resp.Child, resp.NewFD, respFD[0], err
}

func (fs *filesystem) closeFDLisa(ctx context.Context, fd lisafs.FDID) error {
	fs.fdsMu.Lock()
	fs.fdsToClose = append(fs.fdsToClose, fd)
	if len(fs.fdsToClose) < fdCacheSize {
		fs.fdsMu.Unlock()
		return nil
	}

	// Flush the cache. We should not hold fdsMu while making an RPC, so be sure
	// to copy the fdsToClose to another buffer before unlocking fdsMu.
	var toCloseArr [fdCacheSize]lisafs.FDID
	toClose := toCloseArr[:len(fs.fdsToClose)]
	copy(toClose, fs.fdsToClose)

	// Clear fdsToClose so other FDIDs can be appended.
	fs.fdsToClose = fs.fdsToClose[:0]
	fs.fdsMu.Unlock()

	req := lisafs.CloseReq{FDs: toClose}
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.Close, uint32(req.SizeBytes()), req.MarshalBytes, nil, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (fs *filesystem) statToLisa(ctx context.Context, stat *lisafs.Statx, fd lisafs.FDID) error {
	req := lisafs.StatReq{FD: fd}
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.Fstat, uint32(req.SizeBytes()), req.MarshalUnsafe, stat.UnmarshalUnsafe, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (fs *filesystem) syncMultipleFDsLisa(ctx context.Context, fds []lisafs.FDID) error {
	if len(fds) == 0 {
		return nil
	}
	req := lisafs.FsyncReq{FDs: fds}
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.Fsync, uint32(req.SizeBytes()), req.MarshalBytes, nil, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (fs *filesystem) syncFDLisa(ctx context.Context, fd lisafs.FDID) error {
	req := lisafs.FsyncReq{FDs: []lisafs.FDID{fd}}
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.Fsync, uint32(req.SizeBytes()), req.MarshalBytes, nil, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (fs *filesystem) readLisa(ctx context.Context, fd lisafs.FDID, dst []byte, offset uint64) (uint64, error) {
	req := lisafs.PReadReq{
		Offset: offset,
		FD:     fd,
		Count:  uint32(len(dst)),
	}

	resp := lisafs.PReadResp{
		// This will be unmarshalled into. Already set Buf so that we don't need to
		// allocate a temporary buffer during unmarshalling.
		// lisafs.PReadResp.UnmarshalBytes expects this to be set.
		Buf: dst,
	}

	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.PRead, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.UnmarshalBytes, nil)
	ctx.UninterruptibleSleepFinish(false)
	return uint64(resp.NumBytes), err
}

func (fs *filesystem) writeLisa(ctx context.Context, fd lisafs.FDID, src []byte, offset uint64) (uint64, error) {
	req := lisafs.PWriteReq{
		Offset:   primitive.Uint64(offset),
		FD:       fd,
		NumBytes: primitive.Uint32(len(src)),
		Buf:      src,
	}

	var resp lisafs.PWriteResp
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.PWrite, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalUnsafe, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.Count, err
}

func (fs *filesystem) mkdirAtLisa(ctx context.Context, dirFD lisafs.FDID, name string, mode linux.FileMode, uid auth.KUID, gid auth.KGID) (lisafs.Inode, error) {
	var req lisafs.MkdirAtReq
	req.DirFD = dirFD
	req.Name = lisafs.SizedString(name)
	req.Mode = primitive.Uint32(mode)
	req.UID = lisafs.UID(uid)
	req.GID = lisafs.GID(gid)

	var resp lisafs.MkdirAtResp
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.MkdirAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalUnsafe, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.ChildDir, err
}

func (fs *filesystem) symlinkAtLisa(ctx context.Context, dirFD lisafs.FDID, name, target string, uid auth.KUID, gid auth.KGID) (lisafs.Inode, error) {
	req := lisafs.SymlinkAtReq{
		DirFD:  dirFD,
		Name:   lisafs.SizedString(name),
		Target: lisafs.SizedString(target),
		UID:    lisafs.UID(uid),
		GID:    lisafs.GID(gid),
	}

	var resp lisafs.SymlinkAtResp
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.SymlinkAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalUnsafe, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.Symlink, err
}

func (fs *filesystem) linkAtLisa(ctx context.Context, dirFD lisafs.FDID, target lisafs.FDID, name string) (lisafs.Inode, error) {
	req := lisafs.LinkAtReq{
		DirFD:  dirFD,
		Target: target,
		Name:   lisafs.SizedString(name),
	}

	var resp lisafs.LinkAtResp
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.LinkAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalUnsafe, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.Link, err
}

func (fs *filesystem) mknodAtLisa(ctx context.Context, dirFD lisafs.FDID, name string, mode linux.FileMode, uid auth.KUID, gid auth.KGID, minor, major uint32) (lisafs.Inode, error) {
	var req lisafs.MknodAtReq
	req.DirFD = dirFD
	req.Name = lisafs.SizedString(name)
	req.Mode = primitive.Uint32(mode)
	req.UID = lisafs.UID(uid)
	req.GID = lisafs.GID(gid)
	req.Minor = primitive.Uint32(minor)
	req.Major = primitive.Uint32(major)

	var resp lisafs.MknodAtResp
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.MknodAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalUnsafe, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.Child, err
}

func (fs *filesystem) setStatLisa(ctx context.Context, fd lisafs.FDID, stat *linux.Statx) (uint32, error) {
	req := lisafs.SetStatReq{
		FD:   fd,
		Mask: stat.Mask,
		Mode: uint32(stat.Mode),
		UID:  lisafs.UID(stat.UID),
		GID:  lisafs.GID(stat.GID),
		Size: stat.Size,
		Atime: linux.Timespec{
			Sec:  stat.Atime.Sec,
			Nsec: int64(stat.Atime.Nsec),
		},
		Mtime: linux.Timespec{
			Sec:  stat.Mtime.Sec,
			Nsec: int64(stat.Mtime.Nsec),
		},
	}

	var resp lisafs.SetStatResp
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.SetStat, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.UnmarshalUnsafe, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.FailureMask, err
}

func (fs *filesystem) walkMultipleLisa(ctx context.Context, dirFD lisafs.FDID, names []string) ([]lisafs.Inode, error) {
	req := lisafs.WalkReq{
		DirFD: dirFD,
		Path:  lisafs.StringArray(names),
	}

	var resp lisafs.WalkResp
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.Walk, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalBytes, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.Inodes, err
}

func (fs *filesystem) walkLisa(ctx context.Context, dirFD lisafs.FDID, name string) (lisafs.Inode, error) {
	req := lisafs.WalkReq{
		DirFD: dirFD,
		Path:  []string{name},
	}

	var inode [1]lisafs.Inode
	resp := lisafs.WalkResp{Inodes: inode[:]}
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.Walk, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalBytes, nil)
	ctx.UninterruptibleSleepFinish(false)
	if err == nil {
		if n := len(resp.Inodes); n > 1 {
			for i := range resp.Inodes {
				fs.closeFDLisa(ctx, resp.Inodes[i].ControlFD)
			}
			log.Warningf("requested to walk one component, but got %d results", n)
			return lisafs.Inode{}, unix.EIO
		} else if n == 0 {
			return lisafs.Inode{}, unix.ENOENT
		}
	}
	return inode[0], err
}

func (fs *filesystem) walkStatLisa(ctx context.Context, dirFD lisafs.FDID, names []string) ([]lisafs.Statx, error) {
	req := lisafs.WalkReq{
		DirFD: dirFD,
		Path:  lisafs.StringArray(names),
	}

	var resp lisafs.WalkStatResp
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.WalkStat, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalBytes, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.Stats, err
}

func (fs *filesystem) statFSToLisa(ctx context.Context, fd lisafs.FDID, statFS *lisafs.StatFS) error {
	req := lisafs.FStatFSReq{FD: fd}
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.FStatFS, uint32(req.SizeBytes()), req.MarshalUnsafe, statFS.UnmarshalUnsafe, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (fs *filesystem) allocateLisa(ctx context.Context, fd lisafs.FDID, mode, offset, length uint64) error {
	req := lisafs.FAllocateReq{
		FD:     fd,
		Mode:   uint32(mode),
		Offset: offset,
		Length: length,
	}
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.FAllocate, uint32(req.SizeBytes()), req.MarshalUnsafe, nil, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (fs *filesystem) readLinkAtLisa(ctx context.Context, fd lisafs.FDID) (string, error) {
	req := lisafs.ReadLinkAtReq{FD: fd}
	var resp lisafs.ReadLinkAtResp
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.ReadLinkAt, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.UnmarshalBytes, nil)
	ctx.UninterruptibleSleepFinish(false)
	return string(resp.Target), err
}

func (fs *filesystem) flushLisa(ctx context.Context, fd lisafs.FDID) error {
	if !fs.clientLisa.IsSupported(lisafs.FFlush) {
		// If FFlush is not supported, it probably means that it would be a noop.
		return nil
	}
	req := lisafs.FFlushReq{FD: fd}
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.FFlush, uint32(req.SizeBytes()), req.MarshalUnsafe, nil, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (fs *filesystem) connectLisa(ctx context.Context, fd lisafs.FDID, sockType linux.SockType) (int, error) {
	req := lisafs.ConnectReq{FD: fd, SockType: uint32(sockType)}
	sockFD := [1]int{-1}
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.Connect, uint32(req.SizeBytes()), req.MarshalUnsafe, nil, sockFD[:])
	ctx.UninterruptibleSleepFinish(false)
	if err == nil && sockFD[0] < 0 {
		err = unix.EBADF
	}
	return sockFD[0], err
}

func (fs *filesystem) unlinkAtLisa(ctx context.Context, fd lisafs.FDID, name string, flags uint32) error {
	req := lisafs.UnlinkAtReq{
		DirFD: fd,
		Name:  lisafs.SizedString(name),
		Flags: primitive.Uint32(flags),
	}

	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.UnlinkAt, uint32(req.SizeBytes()), req.MarshalBytes, nil, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (fs *filesystem) renameAtLisa(ctx context.Context, renamed lisafs.FDID, newDir lisafs.FDID, newName string) error {
	req := lisafs.RenameAtReq{
		Renamed: renamed,
		NewDir:  newDir,
		NewName: lisafs.SizedString(newName),
	}

	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.RenameAt, uint32(req.SizeBytes()), req.MarshalBytes, nil, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (fs *filesystem) getdents64Lisa(ctx context.Context, dirFD lisafs.FDID, count int32) ([]lisafs.Dirent64, error) {
	req := lisafs.Getdents64Req{
		DirFD: dirFD,
		Count: count,
	}

	var resp lisafs.Getdents64Resp
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.Getdents64, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.UnmarshalBytes, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.Dirents, err
}

func (fs *filesystem) listXattrLisa(ctx context.Context, fd lisafs.FDID, size uint64) ([]string, error) {
	req := lisafs.FListXattrReq{
		FD:   fd,
		Size: size,
	}

	var resp lisafs.FListXattrResp
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.FListXattr, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.UnmarshalBytes, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.Xattrs, err
}

func (fs *filesystem) getXattrLisa(ctx context.Context, fd lisafs.FDID, name string, size uint64) (string, error) {
	req := lisafs.FGetXattrReq{
		FD:      fd,
		Name:    lisafs.SizedString(name),
		BufSize: primitive.Uint32(size),
	}

	var resp lisafs.FGetXattrResp
	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.FGetXattr, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalBytes, nil)
	ctx.UninterruptibleSleepFinish(false)
	return string(resp.Value), err
}

func (fs *filesystem) setXattrLisa(ctx context.Context, fd lisafs.FDID, name string, value string, flags uint32) error {
	req := lisafs.FSetXattrReq{
		FD:    fd,
		Name:  lisafs.SizedString(name),
		Value: lisafs.SizedString(value),
		Flags: primitive.Uint32(flags),
	}

	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.FSetXattr, uint32(req.SizeBytes()), req.MarshalBytes, nil, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (fs *filesystem) removeXattrLisa(ctx context.Context, fd lisafs.FDID, name string) error {
	req := lisafs.FRemoveXattrReq{
		FD:   fd,
		Name: lisafs.SizedString(name),
	}

	ctx.UninterruptibleSleepStart(false)
	err := fs.clientLisa.SndRcvMessage(lisafs.FRemoveXattr, uint32(req.SizeBytes()), req.MarshalBytes, nil, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}
