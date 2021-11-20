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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// ClientFD is a wrapper around FDID that provides client-side utilities
// so that RPC making is easier.
type ClientFD struct {
	fd     FDID
	client *Client
}

// ID returns the underlying FDID.
func (f *ClientFD) ID() FDID {
	return f.fd
}

// Client returns the backing Client.
func (f *ClientFD) Client() *Client {
	return f.client
}

// NewFD initializes a new ClientFD.
func (c *Client) NewFD(fd FDID) ClientFD {
	return ClientFD{
		client: c,
		fd:     fd,
	}
}

// Ok returns true if the underlying FD is ok.
func (f *ClientFD) Ok() bool {
	return f.fd.Ok()
}

// CloseBatched queues this FD to be closed on the server and resets f.fd.
// This maybe invoke the Close RPC if the queue is full.
func (f *ClientFD) CloseBatched(ctx context.Context) {
	f.client.CloseFDBatched(ctx, f.fd)
	f.fd = InvalidFDID
}

// Close closes this FD immediately (invoking a Close RPC). Consider using
// CloseBatched if closing this FD on remote right away is not critical.
func (f *ClientFD) Close(ctx context.Context) error {
	fdArr := [1]FDID{f.fd}
	req := CloseReq{FDs: fdArr[:]}

	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(Close, uint32(req.SizeBytes()), req.MarshalBytes, NoopUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

// OpenAt makes the OpenAt RPC.
func (f *ClientFD) OpenAt(ctx context.Context, flags uint32) (FDID, int, error) {
	req := OpenAtReq{
		FD:    f.fd,
		Flags: flags,
	}
	var respFD [1]int
	var resp OpenAtResp
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(OpenAt, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.CheckedUnmarshal, respFD[:])
	ctx.UninterruptibleSleepFinish(false)
	return resp.NewFD, respFD[0], err
}

// OpenCreateAt makes the OpenCreateAt RPC.
func (f *ClientFD) OpenCreateAt(ctx context.Context, name string, flags uint32, mode linux.FileMode, uid UID, gid GID) (Inode, FDID, int, error) {
	var req OpenCreateAtReq
	req.DirFD = f.fd
	req.Name = SizedString(name)
	req.Flags = primitive.Uint32(flags)
	req.Mode = mode
	req.UID = uid
	req.GID = gid

	var respFD [1]int
	var resp OpenCreateAtResp
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(OpenCreateAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, respFD[:])
	ctx.UninterruptibleSleepFinish(false)
	return resp.Child, resp.NewFD, respFD[0], err
}

// StatTo makes the Fstat RPC and populates stat with the result.
func (f *ClientFD) StatTo(ctx context.Context, stat *linux.Statx) error {
	req := StatReq{FD: f.fd}
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(FStat, uint32(req.SizeBytes()), req.MarshalUnsafe, stat.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

// Sync makes the Fsync RPC.
func (f *ClientFD) Sync(ctx context.Context) error {
	req := FsyncReq{FDs: []FDID{f.fd}}
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(FSync, uint32(req.SizeBytes()), req.MarshalBytes, NoopUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

// chunkify applies fn to buf in chunks based on chunkSize.
func chunkify(chunkSize uint64, buf []byte, fn func([]byte, uint64) (uint64, error)) (uint64, error) {
	toProcess := uint64(len(buf))
	var (
		totalProcessed uint64
		curProcessed   uint64
		off            uint64
		err            error
	)
	for {
		if totalProcessed == toProcess {
			return totalProcessed, nil
		}

		if totalProcessed+chunkSize > toProcess {
			curProcessed, err = fn(buf[totalProcessed:], off)
		} else {
			curProcessed, err = fn(buf[totalProcessed:totalProcessed+chunkSize], off)
		}
		totalProcessed += curProcessed
		off += curProcessed

		if err != nil {
			return totalProcessed, err
		}

		// Return partial result immediately.
		if curProcessed < chunkSize {
			return totalProcessed, nil
		}

		// If we received more bytes than we ever requested, this is a problem.
		if totalProcessed > toProcess {
			panic(fmt.Sprintf("bytes completed (%d)) > requested (%d)", totalProcessed, toProcess))
		}
	}
}

// Read makes the PRead RPC.
func (f *ClientFD) Read(ctx context.Context, dst []byte, offset uint64) (uint64, error) {
	var resp PReadResp
	// maxDataReadSize represents the maximum amount of data we can read at once
	// (maximum message size - metadata size present in resp). Uninitialized
	// resp.SizeBytes() correctly returns the metadata size only (since the read
	// buffer is empty).
	maxDataReadSize := uint64(f.client.maxMessageSize) - uint64(resp.SizeBytes())
	return chunkify(maxDataReadSize, dst, func(buf []byte, curOff uint64) (uint64, error) {
		req := PReadReq{
			Offset: offset + curOff,
			FD:     f.fd,
			Count:  uint32(len(buf)),
		}

		// This will be unmarshalled into. Already set Buf so that we don't need to
		// allocate a temporary buffer during unmarshalling.
		// PReadResp.CheckedUnmarshal expects this to be set.
		resp.Buf = buf
		ctx.UninterruptibleSleepStart(false)
		err := f.client.SndRcvMessage(PRead, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.CheckedUnmarshal, nil)
		ctx.UninterruptibleSleepFinish(false)
		return uint64(resp.NumBytes), err
	})
}

// Write makes the PWrite RPC.
func (f *ClientFD) Write(ctx context.Context, src []byte, offset uint64) (uint64, error) {
	var req PWriteReq
	// maxDataWriteSize represents the maximum amount of data we can write at
	// once (maximum message size - metadata size present in req). Uninitialized
	// req.SizeBytes() correctly returns the metadata size only (since the write
	// buffer is empty).
	maxDataWriteSize := uint64(f.client.maxMessageSize) - uint64(req.SizeBytes())
	return chunkify(maxDataWriteSize, src, func(buf []byte, curOff uint64) (uint64, error) {
		req = PWriteReq{
			Offset:   primitive.Uint64(offset + curOff),
			FD:       f.fd,
			NumBytes: primitive.Uint32(len(buf)),
			Buf:      buf,
		}

		var resp PWriteResp
		ctx.UninterruptibleSleepStart(false)
		err := f.client.SndRcvMessage(PWrite, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, nil)
		ctx.UninterruptibleSleepFinish(false)
		return resp.Count, err
	})
}

// MkdirAt makes the MkdirAt RPC.
func (f *ClientFD) MkdirAt(ctx context.Context, name string, mode linux.FileMode, uid UID, gid GID) (*Inode, error) {
	var req MkdirAtReq
	req.DirFD = f.fd
	req.Name = SizedString(name)
	req.Mode = mode
	req.UID = uid
	req.GID = gid

	var resp MkdirAtResp
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(MkdirAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return &resp.ChildDir, err
}

// SymlinkAt makes the SymlinkAt RPC.
func (f *ClientFD) SymlinkAt(ctx context.Context, name, target string, uid UID, gid GID) (*Inode, error) {
	req := SymlinkAtReq{
		DirFD:  f.fd,
		Name:   SizedString(name),
		Target: SizedString(target),
		UID:    uid,
		GID:    gid,
	}

	var resp SymlinkAtResp
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(SymlinkAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return &resp.Symlink, err
}

// LinkAt makes the LinkAt RPC.
func (f *ClientFD) LinkAt(ctx context.Context, targetFD FDID, name string) (*Inode, error) {
	req := LinkAtReq{
		DirFD:  f.fd,
		Target: targetFD,
		Name:   SizedString(name),
	}

	var resp LinkAtResp
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(LinkAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return &resp.Link, err
}

// MknodAt makes the MknodAt RPC.
func (f *ClientFD) MknodAt(ctx context.Context, name string, mode linux.FileMode, uid UID, gid GID, minor, major uint32) (*Inode, error) {
	var req MknodAtReq
	req.DirFD = f.fd
	req.Name = SizedString(name)
	req.Mode = mode
	req.UID = uid
	req.GID = gid
	req.Minor = primitive.Uint32(minor)
	req.Major = primitive.Uint32(major)

	var resp MknodAtResp
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(MknodAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return &resp.Child, err
}

// SetStat makes the SetStat RPC.
func (f *ClientFD) SetStat(ctx context.Context, stat *linux.Statx) (uint32, error, error) {
	req := SetStatReq{
		FD:   f.fd,
		Mask: stat.Mask,
		Mode: uint32(stat.Mode),
		UID:  UID(stat.UID),
		GID:  GID(stat.GID),
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

	var resp SetStatResp
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(SetStat, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.FailureMask, unix.Errno(resp.FailureErrNo), err
}

// WalkMultiple makes the Walk RPC with multiple path components.
func (f *ClientFD) WalkMultiple(ctx context.Context, names []string) (WalkStatus, []Inode, error) {
	req := WalkReq{
		DirFD: f.fd,
		Path:  StringArray(names),
	}

	var resp WalkResp
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(Walk, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.Status, resp.Inodes, err
}

// Walk makes the Walk RPC with just one path component to walk.
func (f *ClientFD) Walk(ctx context.Context, name string) (*Inode, error) {
	req := WalkReq{
		DirFD: f.fd,
		Path:  []string{name},
	}

	var inode [1]Inode
	resp := WalkResp{Inodes: inode[:]}
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(Walk, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		return nil, err
	}

	switch resp.Status {
	case WalkComponentDoesNotExist:
		return nil, unix.ENOENT
	case WalkComponentSymlink:
		// f is not a directory which can be walked on.
		return nil, unix.ENOTDIR
	}

	if n := len(resp.Inodes); n > 1 {
		for i := range resp.Inodes {
			f.client.CloseFDBatched(ctx, resp.Inodes[i].ControlFD)
		}
		log.Warningf("requested to walk one component, but got %d results", n)
		return nil, unix.EIO
	} else if n == 0 {
		log.Warningf("walk has success status but no results returned")
		return nil, unix.ENOENT
	}
	return &inode[0], err
}

// WalkStat makes the WalkStat RPC with multiple path components to walk.
func (f *ClientFD) WalkStat(ctx context.Context, names []string) ([]linux.Statx, error) {
	req := WalkReq{
		DirFD: f.fd,
		Path:  StringArray(names),
	}

	var resp WalkStatResp
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(WalkStat, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.Stats, err
}

// StatFSTo makes the FStatFS RPC and populates statFS with the result.
func (f *ClientFD) StatFSTo(ctx context.Context, statFS *StatFS) error {
	req := FStatFSReq{FD: f.fd}
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(FStatFS, uint32(req.SizeBytes()), req.MarshalUnsafe, statFS.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

// Allocate makes the FAllocate RPC.
func (f *ClientFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	req := FAllocateReq{
		FD:     f.fd,
		Mode:   mode,
		Offset: offset,
		Length: length,
	}
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(FAllocate, uint32(req.SizeBytes()), req.MarshalUnsafe, NoopUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

// ReadLinkAt makes the ReadLinkAt RPC.
func (f *ClientFD) ReadLinkAt(ctx context.Context) (string, error) {
	req := ReadLinkAtReq{FD: f.fd}
	var resp ReadLinkAtResp
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(ReadLinkAt, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return string(resp.Target), err
}

// Flush makes the Flush RPC.
func (f *ClientFD) Flush(ctx context.Context) error {
	if !f.client.IsSupported(Flush) {
		// If Flush is not supported, it probably means that it would be a noop.
		return nil
	}
	req := FlushReq{FD: f.fd}
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(Flush, uint32(req.SizeBytes()), req.MarshalUnsafe, NoopUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

// Connect makes the Connect RPC.
func (f *ClientFD) Connect(ctx context.Context, sockType linux.SockType) (int, error) {
	req := ConnectReq{FD: f.fd, SockType: uint32(sockType)}
	var sockFD [1]int
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(Connect, uint32(req.SizeBytes()), req.MarshalUnsafe, NoopUnmarshal, sockFD[:])
	ctx.UninterruptibleSleepFinish(false)
	if err == nil && sockFD[0] < 0 {
		err = unix.EBADF
	}
	return sockFD[0], err
}

// UnlinkAt makes the UnlinkAt RPC.
func (f *ClientFD) UnlinkAt(ctx context.Context, name string, flags uint32) error {
	req := UnlinkAtReq{
		DirFD: f.fd,
		Name:  SizedString(name),
		Flags: primitive.Uint32(flags),
	}

	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(UnlinkAt, uint32(req.SizeBytes()), req.MarshalBytes, NoopUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

// RenameTo makes the RenameAt RPC which renames f to newDirFD directory with
// name newName.
func (f *ClientFD) RenameTo(ctx context.Context, newDirFD FDID, newName string) error {
	req := RenameAtReq{
		Renamed: f.fd,
		NewDir:  newDirFD,
		NewName: SizedString(newName),
	}

	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(RenameAt, uint32(req.SizeBytes()), req.MarshalBytes, NoopUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

// Getdents64 makes the Getdents64 RPC.
func (f *ClientFD) Getdents64(ctx context.Context, count int32) ([]Dirent64, error) {
	req := Getdents64Req{
		DirFD: f.fd,
		Count: count,
	}

	var resp Getdents64Resp
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(Getdents64, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.Dirents, err
}

// ListXattr makes the FListXattr RPC.
func (f *ClientFD) ListXattr(ctx context.Context, size uint64) ([]string, error) {
	req := FListXattrReq{
		FD:   f.fd,
		Size: size,
	}

	var resp FListXattrResp
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(FListXattr, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return resp.Xattrs, err
}

// GetXattr makes the FGetXattr RPC.
func (f *ClientFD) GetXattr(ctx context.Context, name string, size uint64) (string, error) {
	req := FGetXattrReq{
		FD:      f.fd,
		Name:    SizedString(name),
		BufSize: primitive.Uint32(size),
	}

	var resp FGetXattrResp
	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(FGetXattr, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return string(resp.Value), err
}

// SetXattr makes the FSetXattr RPC.
func (f *ClientFD) SetXattr(ctx context.Context, name string, value string, flags uint32) error {
	req := FSetXattrReq{
		FD:    f.fd,
		Name:  SizedString(name),
		Value: SizedString(value),
		Flags: primitive.Uint32(flags),
	}

	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(FSetXattr, uint32(req.SizeBytes()), req.MarshalBytes, NoopUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

// RemoveXattr makes the FRemoveXattr RPC.
func (f *ClientFD) RemoveXattr(ctx context.Context, name string) error {
	req := FRemoveXattrReq{
		FD:   f.fd,
		Name: SizedString(name),
	}

	ctx.UninterruptibleSleepStart(false)
	err := f.client.SndRcvMessage(FRemoveXattr, uint32(req.SizeBytes()), req.MarshalBytes, NoopUnmarshal, nil)
	ctx.UninterruptibleSleepFinish(false)
	return err
}
