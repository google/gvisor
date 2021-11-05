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
	"math"
	"os"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// Messages have two parts:
//  * A transport header used to decipher received messages.
//  * A byte array referred to as "payload" which contains the actual message.
//
// "dataLen" refers to the size of both combined.

// MID (message ID) is used to identify messages to parse from payload.
//
// +marshal slice:MIDSlice
type MID uint16

// These constants are used to identify their corresponding message types.
const (
	// Error is only used in responses to pass errors to client.
	Error MID = 0

	// Mount is used to establish connection between the client and server mount
	// point. lisafs requires that the client makes a successful Mount RPC before
	// making other RPCs.
	Mount MID = 1

	// Channel requests to start a new communicational channel.
	Channel MID = 2

	// FStat requests the stat(2) results for a specified file.
	FStat MID = 3

	// SetStat requests to change file attributes. Note that there is no one
	// corresponding Linux syscall. This is a conglomeration of fchmod(2),
	// fchown(2), ftruncate(2) and futimesat(2).
	SetStat MID = 4

	// Walk requests to walk the specified path starting from the specified
	// directory. Server-side path traversal is terminated preemptively on
	// symlinks entries because they can cause non-linear traversal.
	Walk MID = 5

	// WalkStat is the same as Walk, except the following differences:
	//  * If the first path component is "", then it also returns stat results
	//    for the directory where the walk starts.
	//  * Does not return Inode, just the Stat results for each path component.
	WalkStat MID = 6

	// OpenAt is analogous to openat(2). It does not perform any walk. It merely
	// duplicates the control FD with the open flags passed.
	OpenAt MID = 7

	// OpenCreateAt is analogous to openat(2) with O_CREAT|O_EXCL added to flags.
	// It also returns the newly created file inode.
	OpenCreateAt MID = 8

	// Close is analogous to close(2) but can work on multiple FDs.
	Close MID = 9

	// FSync is analogous to fsync(2) but can work on multiple FDs.
	FSync MID = 10

	// PWrite is analogous to pwrite(2).
	PWrite MID = 11

	// PRead is analogous to pread(2).
	PRead MID = 12

	// MkdirAt is analogous to mkdirat(2).
	MkdirAt MID = 13

	// MknodAt is analogous to mknodat(2).
	MknodAt MID = 14

	// SymlinkAt is analogous to symlinkat(2).
	SymlinkAt MID = 15

	// LinkAt is analogous to linkat(2).
	LinkAt MID = 16

	// FStatFS is analogous to fstatfs(2).
	FStatFS MID = 17

	// FAllocate is analogous to fallocate(2).
	FAllocate MID = 18

	// ReadLinkAt is analogous to readlinkat(2).
	ReadLinkAt MID = 19

	// Flush cleans up the file state. Its behavior is implementation
	// dependent and might not even be supported in server implementations.
	Flush MID = 20

	// Connect is loosely analogous to connect(2).
	Connect MID = 21

	// UnlinkAt is analogous to unlinkat(2).
	UnlinkAt MID = 22

	// RenameAt is loosely analogous to renameat(2).
	RenameAt MID = 23

	// Getdents64 is analogous to getdents64(2).
	Getdents64 MID = 24

	// FGetXattr is analogous to fgetxattr(2).
	FGetXattr MID = 25

	// FSetXattr is analogous to fsetxattr(2).
	FSetXattr MID = 26

	// FListXattr is analogous to flistxattr(2).
	FListXattr MID = 27

	// FRemoveXattr is analogous to fremovexattr(2).
	FRemoveXattr MID = 28
)

const (
	// NoUID is a sentinel used to indicate no valid UID.
	NoUID UID = math.MaxUint32

	// NoGID is a sentinel used to indicate no valid GID.
	NoGID GID = math.MaxUint32
)

// MaxMessageSize is the recommended max message size that can be used by
// connections. Server implementations may choose to use other values.
func MaxMessageSize() uint32 {
	// Return HugePageSize - PageSize so that when flipcall packet window is
	// created with MaxMessageSize() + flipcall header size + channel header
	// size, HugePageSize is allocated and can be backed by a single huge page
	// if supported by the underlying memfd.
	return uint32(hostarch.HugePageSize - os.Getpagesize())
}

// TODO(gvisor.dev/issue/6450): Once this is resolved:
// * Update manual implementations and function signatures.
// * Update RPC handlers and appropriate callers to handle errors correctly.

// UID represents a user ID.
//
// +marshal
type UID uint32

// Ok returns true if uid is not NoUID.
func (uid UID) Ok() bool {
	return uid != NoUID
}

// GID represents a group ID.
//
// +marshal
type GID uint32

// Ok returns true if gid is not NoGID.
func (gid GID) Ok() bool {
	return gid != NoGID
}

// NoopMarshal is a noop implementation of marshal.Marshallable.MarshalBytes.
func NoopMarshal(b []byte) []byte { return b }

// NoopUnmarshal is a noop implementation of marshal.Marshallable.UnmarshalBytes.
func NoopUnmarshal(b []byte) []byte { return b }

// SizedString represents a string in memory. The marshalled string bytes are
// preceded by a uint32 signifying the string length.
type SizedString string

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SizedString) SizeBytes() int {
	return (*primitive.Uint32)(nil).SizeBytes() + len(*s)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SizedString) MarshalBytes(dst []byte) []byte {
	strLen := primitive.Uint32(len(*s))
	dst = strLen.MarshalUnsafe(dst)
	// Copy without any allocation.
	return dst[copy(dst[:strLen], *s):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SizedString) UnmarshalBytes(src []byte) []byte {
	var strLen primitive.Uint32
	src = strLen.UnmarshalUnsafe(src)
	// Take the hit, this leads to an allocation + memcpy. No way around it.
	*s = SizedString(src[:strLen])
	return src[strLen:]
}

// StringArray represents an array of SizedStrings in memory. The marshalled
// array data is preceded by a uint32 signifying the array length.
type StringArray []string

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *StringArray) SizeBytes() int {
	size := (*primitive.Uint32)(nil).SizeBytes()
	for _, str := range *s {
		sstr := SizedString(str)
		size += sstr.SizeBytes()
	}
	return size
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *StringArray) MarshalBytes(dst []byte) []byte {
	arrLen := primitive.Uint32(len(*s))
	dst = arrLen.MarshalUnsafe(dst)
	for _, str := range *s {
		sstr := SizedString(str)
		dst = sstr.MarshalBytes(dst)
	}
	return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *StringArray) UnmarshalBytes(src []byte) []byte {
	var arrLen primitive.Uint32
	src = arrLen.UnmarshalUnsafe(src)

	if cap(*s) < int(arrLen) {
		*s = make([]string, arrLen)
	} else {
		*s = (*s)[:arrLen]
	}

	for i := primitive.Uint32(0); i < arrLen; i++ {
		var sstr SizedString
		src = sstr.UnmarshalBytes(src)
		(*s)[i] = string(sstr)
	}
	return src
}

// Inode represents an inode on the remote filesystem.
//
// +marshal slice:InodeSlice
type Inode struct {
	ControlFD FDID
	_         uint32 // Need to make struct packed.
	Stat      linux.Statx
}

// MountReq represents a Mount request.
type MountReq struct {
	MountPath SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MountReq) SizeBytes() int {
	return m.MountPath.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MountReq) MarshalBytes(dst []byte) []byte {
	return m.MountPath.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MountReq) UnmarshalBytes(src []byte) []byte {
	return m.MountPath.UnmarshalBytes(src)
}

// MountResp represents a Mount response.
type MountResp struct {
	Root Inode
	// MaxMessageSize is the maximum size of messages communicated between the
	// client and server in bytes. This includes the communication header.
	MaxMessageSize primitive.Uint32
	// SupportedMs holds all the supported messages.
	SupportedMs []MID
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MountResp) SizeBytes() int {
	return m.Root.SizeBytes() +
		m.MaxMessageSize.SizeBytes() +
		(*primitive.Uint16)(nil).SizeBytes() +
		(len(m.SupportedMs) * (*MID)(nil).SizeBytes())
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MountResp) MarshalBytes(dst []byte) []byte {
	dst = m.Root.MarshalUnsafe(dst)
	dst = m.MaxMessageSize.MarshalUnsafe(dst)
	numSupported := primitive.Uint16(len(m.SupportedMs))
	dst = numSupported.MarshalBytes(dst)
	n, err := MarshalUnsafeMIDSlice(m.SupportedMs, dst)
	if err != nil {
		panic(err)
	}
	return dst[n:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MountResp) UnmarshalBytes(src []byte) []byte {
	src = m.Root.UnmarshalUnsafe(src)
	src = m.MaxMessageSize.UnmarshalUnsafe(src)
	var numSupported primitive.Uint16
	src = numSupported.UnmarshalBytes(src)
	m.SupportedMs = make([]MID, numSupported)
	n, err := UnmarshalUnsafeMIDSlice(m.SupportedMs, src)
	if err != nil {
		panic(err)
	}
	return src[n:]
}

// ChannelResp is the response to the create channel request.
//
// +marshal
type ChannelResp struct {
	dataOffset int64
	dataLength uint64
}

// ErrorResp is returned to represent an error while handling a request.
//
// +marshal
type ErrorResp struct {
	errno uint32
}

// StatReq requests the stat results for the specified FD.
//
// +marshal
type StatReq struct {
	FD FDID
}

// SetStatReq is used to set attributeds on FDs.
//
// +marshal
type SetStatReq struct {
	FD    FDID
	_     uint32
	Mask  uint32
	Mode  uint32 // Only permissions part is settable.
	UID   UID
	GID   GID
	Size  uint64
	Atime linux.Timespec
	Mtime linux.Timespec
}

// SetStatResp is used to communicate SetStat results. It contains a mask
// representing the failed changes. It also contains the errno of the failed
// set attribute operation. If multiple operations failed then any of those
// errnos can be returned.
//
// +marshal
type SetStatResp struct {
	FailureMask  uint32
	FailureErrNo uint32
}

// WalkReq is used to request to walk multiple path components at once. This
// is used for both Walk and WalkStat.
type WalkReq struct {
	DirFD FDID
	Path  StringArray
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (w *WalkReq) SizeBytes() int {
	return w.DirFD.SizeBytes() + w.Path.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (w *WalkReq) MarshalBytes(dst []byte) []byte {
	dst = w.DirFD.MarshalUnsafe(dst)
	return w.Path.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (w *WalkReq) UnmarshalBytes(src []byte) []byte {
	src = w.DirFD.UnmarshalUnsafe(src)
	return w.Path.UnmarshalBytes(src)
}

// WalkStatus is used to indicate the reason for partial/unsuccessful server
// side Walk operations. Please note that partial/unsuccessful walk operations
// do not necessarily fail the RPC. The RPC is successful with a failure hint
// which can be used by the client to infer server-side state.
type WalkStatus = primitive.Uint8

const (
	// WalkSuccess indicates that all path components were successfully walked.
	WalkSuccess WalkStatus = iota

	// WalkComponentDoesNotExist indicates that the walk was prematurely
	// terminated because an intermediate path component does not exist on
	// server. The results of all previous existing path components is returned.
	WalkComponentDoesNotExist

	// WalkComponentSymlink indicates that the walk was prematurely
	// terminated because an intermediate path component was a symlink. It is not
	// safe to resolve symlinks remotely (unaware of mount points).
	WalkComponentSymlink
)

// WalkResp is used to communicate the inodes walked by the server.
type WalkResp struct {
	Status WalkStatus
	Inodes []Inode
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (w *WalkResp) SizeBytes() int {
	return w.Status.SizeBytes() +
		(*primitive.Uint32)(nil).SizeBytes() + (len(w.Inodes) * (*Inode)(nil).SizeBytes())
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (w *WalkResp) MarshalBytes(dst []byte) []byte {
	dst = w.Status.MarshalUnsafe(dst)

	numInodes := primitive.Uint32(len(w.Inodes))
	dst = numInodes.MarshalUnsafe(dst)

	n, err := MarshalUnsafeInodeSlice(w.Inodes, dst)
	if err != nil {
		panic(err)
	}
	return dst[n:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (w *WalkResp) UnmarshalBytes(src []byte) []byte {
	src = w.Status.UnmarshalUnsafe(src)

	var numInodes primitive.Uint32
	src = numInodes.UnmarshalUnsafe(src)

	if cap(w.Inodes) < int(numInodes) {
		w.Inodes = make([]Inode, numInodes)
	} else {
		w.Inodes = w.Inodes[:numInodes]
	}
	n, err := UnmarshalUnsafeInodeSlice(w.Inodes, src)
	if err != nil {
		panic(err)
	}
	return src[n:]
}

// WalkStatResp is used to communicate stat results for WalkStat.
type WalkStatResp struct {
	Stats []linux.Statx
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (w *WalkStatResp) SizeBytes() int {
	return (*primitive.Uint32)(nil).SizeBytes() + (len(w.Stats) * linux.SizeOfStatx)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (w *WalkStatResp) MarshalBytes(dst []byte) []byte {
	numStats := primitive.Uint32(len(w.Stats))
	dst = numStats.MarshalUnsafe(dst)

	n, err := linux.MarshalUnsafeStatxSlice(w.Stats, dst)
	if err != nil {
		panic(err)
	}
	return dst[n:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (w *WalkStatResp) UnmarshalBytes(src []byte) []byte {
	var numStats primitive.Uint32
	src = numStats.UnmarshalUnsafe(src)

	if cap(w.Stats) < int(numStats) {
		w.Stats = make([]linux.Statx, numStats)
	} else {
		w.Stats = w.Stats[:numStats]
	}
	n, err := linux.UnmarshalUnsafeStatxSlice(w.Stats, src)
	if err != nil {
		panic(err)
	}
	return src[n:]
}

// OpenAtReq is used to open existing FDs with the specified flags.
//
// +marshal
type OpenAtReq struct {
	FD    FDID
	Flags uint32
}

// OpenAtResp is used to communicate the newly created FD.
//
// +marshal
type OpenAtResp struct {
	NewFD FDID
}

// +marshal
type createCommon struct {
	DirFD FDID
	Mode  linux.FileMode
	_     uint16 // Need to make struct packed.
	UID   UID
	GID   GID
}

// OpenCreateAtReq is used to make OpenCreateAt requests.
type OpenCreateAtReq struct {
	createCommon
	Name  SizedString
	Flags primitive.Uint32
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (o *OpenCreateAtReq) SizeBytes() int {
	return o.createCommon.SizeBytes() + o.Name.SizeBytes() + o.Flags.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (o *OpenCreateAtReq) MarshalBytes(dst []byte) []byte {
	dst = o.createCommon.MarshalUnsafe(dst)
	dst = o.Name.MarshalBytes(dst)
	return o.Flags.MarshalUnsafe(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (o *OpenCreateAtReq) UnmarshalBytes(src []byte) []byte {
	src = o.createCommon.UnmarshalUnsafe(src)
	src = o.Name.UnmarshalBytes(src)
	return o.Flags.UnmarshalUnsafe(src)
}

// OpenCreateAtResp is used to communicate successful OpenCreateAt results.
//
// +marshal
type OpenCreateAtResp struct {
	Child Inode
	NewFD FDID
	_     uint32 // Need to make struct packed.
}

// FdArray is a utility struct which implements a marshallable type for
// communicating an array of FDIDs. In memory, the array data is preceded by a
// uint32 denoting the array length.
type FdArray []FDID

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FdArray) SizeBytes() int {
	return (*primitive.Uint32)(nil).SizeBytes() + (len(*f) * (*FDID)(nil).SizeBytes())
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FdArray) MarshalBytes(dst []byte) []byte {
	arrLen := primitive.Uint32(len(*f))
	dst = arrLen.MarshalUnsafe(dst)
	n, err := MarshalUnsafeFDIDSlice(*f, dst)
	if err != nil {
		panic(err)
	}
	return dst[n:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FdArray) UnmarshalBytes(src []byte) []byte {
	var arrLen primitive.Uint32
	src = arrLen.UnmarshalUnsafe(src)
	if cap(*f) < int(arrLen) {
		*f = make(FdArray, arrLen)
	} else {
		*f = (*f)[:arrLen]
	}
	n, err := UnmarshalUnsafeFDIDSlice(*f, src)
	if err != nil {
		panic(err)
	}
	return src[n:]
}

// CloseReq is used to close(2) FDs.
type CloseReq struct {
	FDs FdArray
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *CloseReq) SizeBytes() int {
	return c.FDs.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *CloseReq) MarshalBytes(dst []byte) []byte {
	return c.FDs.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *CloseReq) UnmarshalBytes(src []byte) []byte {
	return c.FDs.UnmarshalBytes(src)
}

// FsyncReq is used to fsync(2) FDs.
type FsyncReq struct {
	FDs FdArray
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FsyncReq) SizeBytes() int {
	return f.FDs.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FsyncReq) MarshalBytes(dst []byte) []byte {
	return f.FDs.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FsyncReq) UnmarshalBytes(src []byte) []byte {
	return f.FDs.UnmarshalBytes(src)
}

// PReadReq is used to pread(2) on an FD.
//
// +marshal
type PReadReq struct {
	Offset uint64
	FD     FDID
	Count  uint32
}

// PReadResp is used to return the result of pread(2).
type PReadResp struct {
	NumBytes primitive.Uint32
	Buf      []byte
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *PReadResp) SizeBytes() int {
	return r.NumBytes.SizeBytes() + int(r.NumBytes)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *PReadResp) MarshalBytes(dst []byte) []byte {
	dst = r.NumBytes.MarshalUnsafe(dst)
	return dst[copy(dst[:r.NumBytes], r.Buf[:r.NumBytes]):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *PReadResp) UnmarshalBytes(src []byte) []byte {
	src = r.NumBytes.UnmarshalUnsafe(src)

	// We expect the client to have already allocated r.Buf. r.Buf probably
	// (optimally) points to usermem. Directly copy into that.
	return src[copy(r.Buf[:r.NumBytes], src[:r.NumBytes]):]
}

// PWriteReq is used to pwrite(2) on an FD.
type PWriteReq struct {
	Offset   primitive.Uint64
	FD       FDID
	NumBytes primitive.Uint32
	Buf      []byte
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (w *PWriteReq) SizeBytes() int {
	return w.Offset.SizeBytes() + w.FD.SizeBytes() + w.NumBytes.SizeBytes() + int(w.NumBytes)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (w *PWriteReq) MarshalBytes(dst []byte) []byte {
	dst = w.Offset.MarshalUnsafe(dst)
	dst = w.FD.MarshalUnsafe(dst)
	dst = w.NumBytes.MarshalUnsafe(dst)
	return dst[copy(dst[:w.NumBytes], w.Buf[:w.NumBytes]):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (w *PWriteReq) UnmarshalBytes(src []byte) []byte {
	src = w.Offset.UnmarshalUnsafe(src)
	src = w.FD.UnmarshalUnsafe(src)
	src = w.NumBytes.UnmarshalUnsafe(src)

	// This is an optimization. Assuming that the server is making this call, it
	// is safe to just point to src rather than allocating and copying.
	w.Buf = src[:w.NumBytes]
	return src[w.NumBytes:]
}

// PWriteResp is used to return the result of pwrite(2).
//
// +marshal
type PWriteResp struct {
	Count uint64
}

// MkdirAtReq is used to make MkdirAt requests.
type MkdirAtReq struct {
	createCommon
	Name SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MkdirAtReq) SizeBytes() int {
	return m.createCommon.SizeBytes() + m.Name.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MkdirAtReq) MarshalBytes(dst []byte) []byte {
	dst = m.createCommon.MarshalUnsafe(dst)
	return m.Name.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MkdirAtReq) UnmarshalBytes(src []byte) []byte {
	src = m.createCommon.UnmarshalUnsafe(src)
	return m.Name.UnmarshalBytes(src)
}

// MkdirAtResp is the response to a successful MkdirAt request.
//
// +marshal
type MkdirAtResp struct {
	ChildDir Inode
}

// MknodAtReq is used to make MknodAt requests.
type MknodAtReq struct {
	createCommon
	Name  SizedString
	Minor primitive.Uint32
	Major primitive.Uint32
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MknodAtReq) SizeBytes() int {
	return m.createCommon.SizeBytes() + m.Name.SizeBytes() + m.Minor.SizeBytes() + m.Major.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MknodAtReq) MarshalBytes(dst []byte) []byte {
	dst = m.createCommon.MarshalUnsafe(dst)
	dst = m.Name.MarshalBytes(dst)
	dst = m.Minor.MarshalUnsafe(dst)
	return m.Major.MarshalUnsafe(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MknodAtReq) UnmarshalBytes(src []byte) []byte {
	src = m.createCommon.UnmarshalUnsafe(src)
	src = m.Name.UnmarshalBytes(src)
	src = m.Minor.UnmarshalUnsafe(src)
	return m.Major.UnmarshalUnsafe(src)
}

// MknodAtResp is the response to a successful MknodAt request.
//
// +marshal
type MknodAtResp struct {
	Child Inode
}

// SymlinkAtReq is used to make SymlinkAt request.
type SymlinkAtReq struct {
	DirFD  FDID
	Name   SizedString
	Target SizedString
	UID    UID
	GID    GID
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SymlinkAtReq) SizeBytes() int {
	return s.DirFD.SizeBytes() + s.Name.SizeBytes() + s.Target.SizeBytes() + s.UID.SizeBytes() + s.GID.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SymlinkAtReq) MarshalBytes(dst []byte) []byte {
	dst = s.DirFD.MarshalUnsafe(dst)
	dst = s.Name.MarshalBytes(dst)
	dst = s.Target.MarshalBytes(dst)
	dst = s.UID.MarshalUnsafe(dst)
	return s.GID.MarshalUnsafe(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SymlinkAtReq) UnmarshalBytes(src []byte) []byte {
	src = s.DirFD.UnmarshalUnsafe(src)
	src = s.Name.UnmarshalBytes(src)
	src = s.Target.UnmarshalBytes(src)
	src = s.UID.UnmarshalUnsafe(src)
	return s.GID.UnmarshalUnsafe(src)
}

// SymlinkAtResp is the response to a successful SymlinkAt request.
//
// +marshal
type SymlinkAtResp struct {
	Symlink Inode
}

// LinkAtReq is used to make LinkAt requests.
type LinkAtReq struct {
	DirFD  FDID
	Target FDID
	Name   SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (l *LinkAtReq) SizeBytes() int {
	return l.DirFD.SizeBytes() + l.Target.SizeBytes() + l.Name.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (l *LinkAtReq) MarshalBytes(dst []byte) []byte {
	dst = l.DirFD.MarshalUnsafe(dst)
	dst = l.Target.MarshalUnsafe(dst)
	return l.Name.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (l *LinkAtReq) UnmarshalBytes(src []byte) []byte {
	src = l.DirFD.UnmarshalUnsafe(src)
	src = l.Target.UnmarshalUnsafe(src)
	return l.Name.UnmarshalBytes(src)
}

// LinkAtResp is used to respond to a successful LinkAt request.
//
// +marshal
type LinkAtResp struct {
	Link Inode
}

// FStatFSReq is used to request StatFS results for the specified FD.
//
// +marshal
type FStatFSReq struct {
	FD FDID
}

// StatFS is responded to a successful FStatFS request.
//
// +marshal
type StatFS struct {
	Type            uint64
	BlockSize       int64
	Blocks          uint64
	BlocksFree      uint64
	BlocksAvailable uint64
	Files           uint64
	FilesFree       uint64
	NameLength      uint64
}

// FAllocateReq is used to request to fallocate(2) an FD. This has no response.
//
// +marshal
type FAllocateReq struct {
	FD     FDID
	_      uint32
	Mode   uint64
	Offset uint64
	Length uint64
}

// ReadLinkAtReq is used to readlinkat(2) at the specified FD.
//
// +marshal
type ReadLinkAtReq struct {
	FD FDID
}

// ReadLinkAtResp is used to communicate ReadLinkAt results.
type ReadLinkAtResp struct {
	Target SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *ReadLinkAtResp) SizeBytes() int {
	return r.Target.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *ReadLinkAtResp) MarshalBytes(dst []byte) []byte {
	return r.Target.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *ReadLinkAtResp) UnmarshalBytes(src []byte) []byte {
	return r.Target.UnmarshalBytes(src)
}

// FlushReq is used to make Flush requests.
//
// +marshal
type FlushReq struct {
	FD FDID
}

// ConnectReq is used to make a Connect request.
//
// +marshal
type ConnectReq struct {
	FD FDID
	// SockType is used to specify the socket type to connect to. As a special
	// case, SockType = 0 means that the socket type does not matter and the
	// requester will accept any socket type.
	SockType uint32
}

// UnlinkAtReq is used to make UnlinkAt request.
type UnlinkAtReq struct {
	DirFD FDID
	Name  SizedString
	Flags primitive.Uint32
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *UnlinkAtReq) SizeBytes() int {
	return u.DirFD.SizeBytes() + u.Name.SizeBytes() + u.Flags.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UnlinkAtReq) MarshalBytes(dst []byte) []byte {
	dst = u.DirFD.MarshalUnsafe(dst)
	dst = u.Name.MarshalBytes(dst)
	return u.Flags.MarshalUnsafe(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UnlinkAtReq) UnmarshalBytes(src []byte) []byte {
	src = u.DirFD.UnmarshalUnsafe(src)
	src = u.Name.UnmarshalBytes(src)
	return u.Flags.UnmarshalUnsafe(src)
}

// RenameAtReq is used to make Rename requests. Note that the request takes in
// the to-be-renamed file's FD instead of oldDir and oldName like renameat(2).
type RenameAtReq struct {
	Renamed FDID
	NewDir  FDID
	NewName SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *RenameAtReq) SizeBytes() int {
	return r.Renamed.SizeBytes() + r.NewDir.SizeBytes() + r.NewName.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RenameAtReq) MarshalBytes(dst []byte) []byte {
	dst = r.Renamed.MarshalUnsafe(dst)
	dst = r.NewDir.MarshalUnsafe(dst)
	return r.NewName.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *RenameAtReq) UnmarshalBytes(src []byte) []byte {
	src = r.Renamed.UnmarshalUnsafe(src)
	src = r.NewDir.UnmarshalUnsafe(src)
	return r.NewName.UnmarshalBytes(src)
}

// Getdents64Req is used to make Getdents64 requests.
//
// +marshal
type Getdents64Req struct {
	DirFD FDID
	// Count is the number of bytes to read. A negative value of Count is used to
	// indicate that the implementation must lseek(0, SEEK_SET) before calling
	// getdents64(2). Implementations must use the absolute value of Count to
	// determine the number of bytes to read.
	Count int32
}

// Dirent64 is analogous to struct linux_dirent64.
type Dirent64 struct {
	Ino      primitive.Uint64
	DevMinor primitive.Uint32
	DevMajor primitive.Uint32
	Off      primitive.Uint64
	Type     primitive.Uint8
	Name     SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (d *Dirent64) SizeBytes() int {
	return d.Ino.SizeBytes() + d.DevMinor.SizeBytes() + d.DevMajor.SizeBytes() + d.Off.SizeBytes() + d.Type.SizeBytes() + d.Name.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (d *Dirent64) MarshalBytes(dst []byte) []byte {
	dst = d.Ino.MarshalUnsafe(dst)
	dst = d.DevMinor.MarshalUnsafe(dst)
	dst = d.DevMajor.MarshalUnsafe(dst)
	dst = d.Off.MarshalUnsafe(dst)
	dst = d.Type.MarshalUnsafe(dst)
	return d.Name.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (d *Dirent64) UnmarshalBytes(src []byte) []byte {
	src = d.Ino.UnmarshalUnsafe(src)
	src = d.DevMinor.UnmarshalUnsafe(src)
	src = d.DevMajor.UnmarshalUnsafe(src)
	src = d.Off.UnmarshalUnsafe(src)
	src = d.Type.UnmarshalUnsafe(src)
	return d.Name.UnmarshalBytes(src)
}

// Getdents64Resp is used to communicate getdents64 results.
type Getdents64Resp struct {
	Dirents []Dirent64
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (g *Getdents64Resp) SizeBytes() int {
	ret := (*primitive.Uint32)(nil).SizeBytes()
	for i := range g.Dirents {
		ret += g.Dirents[i].SizeBytes()
	}
	return ret
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (g *Getdents64Resp) MarshalBytes(dst []byte) []byte {
	numDirents := primitive.Uint32(len(g.Dirents))
	dst = numDirents.MarshalUnsafe(dst)
	for i := range g.Dirents {
		dst = g.Dirents[i].MarshalBytes(dst)
	}
	return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (g *Getdents64Resp) UnmarshalBytes(src []byte) []byte {
	var numDirents primitive.Uint32
	src = numDirents.UnmarshalUnsafe(src)
	if cap(g.Dirents) < int(numDirents) {
		g.Dirents = make([]Dirent64, numDirents)
	} else {
		g.Dirents = g.Dirents[:numDirents]
	}

	for i := range g.Dirents {
		src = g.Dirents[i].UnmarshalBytes(src)
	}
	return src
}

// FGetXattrReq is used to make FGetXattr requests. The response to this is
// just a SizedString containing the xattr value.
type FGetXattrReq struct {
	FD      FDID
	BufSize primitive.Uint32
	Name    SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (g *FGetXattrReq) SizeBytes() int {
	return g.FD.SizeBytes() + g.BufSize.SizeBytes() + g.Name.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (g *FGetXattrReq) MarshalBytes(dst []byte) []byte {
	dst = g.FD.MarshalUnsafe(dst)
	dst = g.BufSize.MarshalUnsafe(dst)
	return g.Name.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (g *FGetXattrReq) UnmarshalBytes(src []byte) []byte {
	src = g.FD.UnmarshalUnsafe(src)
	src = g.BufSize.UnmarshalUnsafe(src)
	return g.Name.UnmarshalBytes(src)
}

// FGetXattrResp is used to respond to FGetXattr request.
type FGetXattrResp struct {
	Value SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (g *FGetXattrResp) SizeBytes() int {
	return g.Value.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (g *FGetXattrResp) MarshalBytes(dst []byte) []byte {
	return g.Value.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (g *FGetXattrResp) UnmarshalBytes(src []byte) []byte {
	return g.Value.UnmarshalBytes(src)
}

// FSetXattrReq is used to make FSetXattr requests. It has no response.
type FSetXattrReq struct {
	FD    FDID
	Flags primitive.Uint32
	Name  SizedString
	Value SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *FSetXattrReq) SizeBytes() int {
	return s.FD.SizeBytes() + s.Flags.SizeBytes() + s.Name.SizeBytes() + s.Value.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *FSetXattrReq) MarshalBytes(dst []byte) []byte {
	dst = s.FD.MarshalUnsafe(dst)
	dst = s.Flags.MarshalUnsafe(dst)
	dst = s.Name.MarshalBytes(dst)
	return s.Value.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *FSetXattrReq) UnmarshalBytes(src []byte) []byte {
	src = s.FD.UnmarshalUnsafe(src)
	src = s.Flags.UnmarshalUnsafe(src)
	src = s.Name.UnmarshalBytes(src)
	return s.Value.UnmarshalBytes(src)
}

// FRemoveXattrReq is used to make FRemoveXattr requests. It has no response.
type FRemoveXattrReq struct {
	FD   FDID
	Name SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *FRemoveXattrReq) SizeBytes() int {
	return r.FD.SizeBytes() + r.Name.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *FRemoveXattrReq) MarshalBytes(dst []byte) []byte {
	dst = r.FD.MarshalUnsafe(dst)
	return r.Name.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *FRemoveXattrReq) UnmarshalBytes(src []byte) []byte {
	src = r.FD.UnmarshalUnsafe(src)
	return r.Name.UnmarshalBytes(src)
}

// FListXattrReq is used to make FListXattr requests.
//
// +marshal
type FListXattrReq struct {
	FD   FDID
	_    uint32
	Size uint64
}

// FListXattrResp is used to respond to FListXattr requests.
type FListXattrResp struct {
	Xattrs StringArray
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (l *FListXattrResp) SizeBytes() int {
	return l.Xattrs.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (l *FListXattrResp) MarshalBytes(dst []byte) []byte {
	return l.Xattrs.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (l *FListXattrResp) UnmarshalBytes(src []byte) []byte {
	return l.Xattrs.UnmarshalBytes(src)
}
