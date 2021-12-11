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
func NoopUnmarshal(b []byte) ([]byte, bool) { return b, true }

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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (s *SizedString) CheckedUnmarshal(src []byte) ([]byte, bool) {
	var strLen primitive.Uint32
	srcRemain, ok := strLen.CheckedUnmarshal(src)
	if !ok || len(srcRemain) < int(strLen) {
		return src, false
	}
	// Take the hit, this leads to an allocation + memcpy. No way around it.
	*s = SizedString(srcRemain[:strLen])
	return srcRemain[strLen:], true
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (s *StringArray) CheckedUnmarshal(src []byte) ([]byte, bool) {
	var arrLen primitive.Uint32
	srcRemain, ok := arrLen.CheckedUnmarshal(src)
	if !ok {
		return src, false
	}

	if cap(*s) < int(arrLen) {
		*s = make([]string, arrLen)
	} else {
		*s = (*s)[:arrLen]
	}

	for i := primitive.Uint32(0); i < arrLen; i++ {
		var sstr SizedString
		srcRemain, ok = sstr.CheckedUnmarshal(srcRemain)
		if !ok {
			return src, false
		}
		(*s)[i] = string(sstr)
	}
	return srcRemain, true
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (m *MountReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	return m.MountPath.CheckedUnmarshal(src)
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
	return MarshalUnsafeMIDSlice(m.SupportedMs, dst)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (m *MountResp) CheckedUnmarshal(src []byte) ([]byte, bool) {
	m.SupportedMs = m.SupportedMs[:0]
	if m.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := m.Root.UnmarshalUnsafe(src)
	srcRemain = m.MaxMessageSize.UnmarshalUnsafe(srcRemain)
	var numSupported primitive.Uint16
	srcRemain = numSupported.UnmarshalBytes(srcRemain)
	if int(numSupported)*(*MID)(nil).SizeBytes() > len(srcRemain) {
		return src, false
	}
	if cap(m.SupportedMs) < int(numSupported) {
		m.SupportedMs = make([]MID, numSupported)
	} else {
		m.SupportedMs = m.SupportedMs[:numSupported]
	}
	return UnmarshalUnsafeMIDSlice(m.SupportedMs, srcRemain), true
}

// ChannelResp is the response to the create channel request.
//
// +marshal boundCheck
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
// +marshal boundCheck
type StatReq struct {
	FD FDID
}

// SetStatReq is used to set attributeds on FDs.
//
// +marshal boundCheck
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
// +marshal boundCheck
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (w *WalkReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	w.Path = w.Path[:0]
	if w.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := w.DirFD.UnmarshalUnsafe(src)
	if srcRemain, ok := w.Path.CheckedUnmarshal(srcRemain); ok {
		return srcRemain, true
	}
	return src, false
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

	return MarshalUnsafeInodeSlice(w.Inodes, dst)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (w *WalkResp) CheckedUnmarshal(src []byte) ([]byte, bool) {
	w.Inodes = w.Inodes[:0]
	if w.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := w.Status.UnmarshalUnsafe(src)

	var numInodes primitive.Uint32
	srcRemain = numInodes.UnmarshalUnsafe(srcRemain)
	if int(numInodes)*(*Inode)(nil).SizeBytes() > len(srcRemain) {
		return src, false
	}
	if cap(w.Inodes) < int(numInodes) {
		w.Inodes = make([]Inode, numInodes)
	} else {
		w.Inodes = w.Inodes[:numInodes]
	}
	return UnmarshalUnsafeInodeSlice(w.Inodes, srcRemain), true
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

	return linux.MarshalUnsafeStatxSlice(w.Stats, dst)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (w *WalkStatResp) CheckedUnmarshal(src []byte) ([]byte, bool) {
	w.Stats = w.Stats[:0]
	if w.SizeBytes() > len(src) {
		return src, false
	}
	var numStats primitive.Uint32
	srcRemain := numStats.UnmarshalUnsafe(src)

	if int(numStats)*linux.SizeOfStatx > len(srcRemain) {
		return src, false
	}
	if cap(w.Stats) < int(numStats) {
		w.Stats = make([]linux.Statx, numStats)
	} else {
		w.Stats = w.Stats[:numStats]
	}
	return linux.UnmarshalUnsafeStatxSlice(w.Stats, srcRemain), true
}

// OpenAtReq is used to open existing FDs with the specified flags.
//
// +marshal boundCheck
type OpenAtReq struct {
	FD    FDID
	Flags uint32
}

// OpenAtResp is used to communicate the newly created FD.
//
// +marshal boundCheck
type OpenAtResp struct {
	OpenFD FDID
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
	Flags primitive.Uint32
	Name  SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (o *OpenCreateAtReq) SizeBytes() int {
	return o.createCommon.SizeBytes() + o.Flags.SizeBytes() + o.Name.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (o *OpenCreateAtReq) MarshalBytes(dst []byte) []byte {
	dst = o.createCommon.MarshalUnsafe(dst)
	dst = o.Flags.MarshalUnsafe(dst)
	return o.Name.MarshalBytes(dst)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (o *OpenCreateAtReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	o.Name = ""
	if o.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := o.createCommon.UnmarshalUnsafe(src)
	srcRemain = o.Flags.UnmarshalUnsafe(srcRemain)
	if srcRemain, ok := o.Name.CheckedUnmarshal(srcRemain); ok {
		return srcRemain, true
	}
	return src, false
}

// OpenCreateAtResp is used to communicate successful OpenCreateAt results.
//
// +marshal boundCheck
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
	return MarshalUnsafeFDIDSlice(*f, dst)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (f *FdArray) CheckedUnmarshal(src []byte) ([]byte, bool) {
	*f = (*f)[:0]
	if f.SizeBytes() > len(src) {
		return src, false
	}
	var arrLen primitive.Uint32
	srcRemain := arrLen.UnmarshalUnsafe(src)
	if int(arrLen)*(*FDID)(nil).SizeBytes() > len(srcRemain) {
		return src, false
	}
	if cap(*f) < int(arrLen) {
		*f = make(FdArray, arrLen)
	} else {
		*f = (*f)[:arrLen]
	}
	return UnmarshalUnsafeFDIDSlice(*f, srcRemain), true
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (c *CloseReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	return c.FDs.CheckedUnmarshal(src)
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (f *FsyncReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	return f.FDs.CheckedUnmarshal(src)
}

// PReadReq is used to pread(2) on an FD.
//
// +marshal boundCheck
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (r *PReadResp) CheckedUnmarshal(src []byte) ([]byte, bool) {
	srcRemain, ok := r.NumBytes.CheckedUnmarshal(src)
	if !ok || int(r.NumBytes) > len(srcRemain) || int(r.NumBytes) > len(r.Buf) {
		return src, false
	}

	// We expect the client to have already allocated r.Buf. r.Buf probably
	// (optimally) points to usermem. Directly copy into that.
	return srcRemain[copy(r.Buf[:r.NumBytes], srcRemain[:r.NumBytes]):], true
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (w *PWriteReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	w.NumBytes = 0
	if w.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := w.Offset.UnmarshalUnsafe(src)
	srcRemain = w.FD.UnmarshalUnsafe(srcRemain)
	srcRemain = w.NumBytes.UnmarshalUnsafe(srcRemain)

	// This is an optimization. Assuming that the server is making this call, it
	// is safe to just point to src rather than allocating and copying.
	if int(w.NumBytes) > len(srcRemain) {
		return src, false
	}
	w.Buf = srcRemain[:w.NumBytes]
	return srcRemain[w.NumBytes:], true
}

// PWriteResp is used to return the result of pwrite(2).
//
// +marshal boundCheck
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (m *MkdirAtReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	m.Name = ""
	if m.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := m.createCommon.UnmarshalUnsafe(src)
	if srcRemain, ok := m.Name.CheckedUnmarshal(srcRemain); ok {
		return srcRemain, true
	}
	return src, false
}

// MkdirAtResp is the response to a successful MkdirAt request.
//
// +marshal boundCheck
type MkdirAtResp struct {
	ChildDir Inode
}

// MknodAtReq is used to make MknodAt requests.
type MknodAtReq struct {
	createCommon
	Minor primitive.Uint32
	Major primitive.Uint32
	Name  SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MknodAtReq) SizeBytes() int {
	return m.createCommon.SizeBytes() + m.Minor.SizeBytes() + m.Major.SizeBytes() + m.Name.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MknodAtReq) MarshalBytes(dst []byte) []byte {
	dst = m.createCommon.MarshalUnsafe(dst)
	dst = m.Minor.MarshalUnsafe(dst)
	dst = m.Major.MarshalUnsafe(dst)
	return m.Name.MarshalBytes(dst)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (m *MknodAtReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	m.Name = ""
	if m.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := m.createCommon.UnmarshalUnsafe(src)
	srcRemain = m.Minor.UnmarshalUnsafe(srcRemain)
	srcRemain = m.Major.UnmarshalUnsafe(srcRemain)
	if srcRemain, ok := m.Name.CheckedUnmarshal(srcRemain); ok {
		return srcRemain, true
	}
	return src, false
}

// MknodAtResp is the response to a successful MknodAt request.
//
// +marshal boundCheck
type MknodAtResp struct {
	Child Inode
}

// SymlinkAtReq is used to make SymlinkAt request.
type SymlinkAtReq struct {
	DirFD  FDID
	UID    UID
	GID    GID
	Name   SizedString
	Target SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SymlinkAtReq) SizeBytes() int {
	return s.DirFD.SizeBytes() + s.UID.SizeBytes() + s.GID.SizeBytes() + s.Name.SizeBytes() + s.Target.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SymlinkAtReq) MarshalBytes(dst []byte) []byte {
	dst = s.DirFD.MarshalUnsafe(dst)
	dst = s.UID.MarshalUnsafe(dst)
	dst = s.GID.MarshalUnsafe(dst)
	dst = s.Name.MarshalBytes(dst)
	return s.Target.MarshalBytes(dst)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (s *SymlinkAtReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	s.Name = ""
	s.Target = ""
	if s.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := s.DirFD.UnmarshalUnsafe(src)
	srcRemain = s.UID.UnmarshalUnsafe(srcRemain)
	srcRemain = s.GID.UnmarshalUnsafe(srcRemain)
	var ok bool
	if srcRemain, ok = s.Name.CheckedUnmarshal(srcRemain); !ok {
		return src, false
	}
	if srcRemain, ok = s.Target.CheckedUnmarshal(srcRemain); !ok {
		return src, false
	}
	return srcRemain, true
}

// SymlinkAtResp is the response to a successful SymlinkAt request.
//
// +marshal boundCheck
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (l *LinkAtReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	l.Name = ""
	if l.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := l.DirFD.UnmarshalUnsafe(src)
	srcRemain = l.Target.UnmarshalUnsafe(srcRemain)
	if srcRemain, ok := l.Name.CheckedUnmarshal(srcRemain); ok {
		return srcRemain, true
	}
	return src, false
}

// LinkAtResp is used to respond to a successful LinkAt request.
//
// +marshal boundCheck
type LinkAtResp struct {
	Link Inode
}

// FStatFSReq is used to request StatFS results for the specified FD.
//
// +marshal boundCheck
type FStatFSReq struct {
	FD FDID
}

// StatFS is responded to a successful FStatFS request.
//
// +marshal boundCheck
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
// +marshal boundCheck
type FAllocateReq struct {
	FD     FDID
	_      uint32
	Mode   uint64
	Offset uint64
	Length uint64
}

// ReadLinkAtReq is used to readlinkat(2) at the specified FD.
//
// +marshal boundCheck
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (r *ReadLinkAtResp) CheckedUnmarshal(src []byte) ([]byte, bool) {
	return r.Target.CheckedUnmarshal(src)
}

// FlushReq is used to make Flush requests.
//
// +marshal boundCheck
type FlushReq struct {
	FD FDID
}

// ConnectReq is used to make a Connect request.
//
// +marshal boundCheck
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
	Flags primitive.Uint32
	Name  SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *UnlinkAtReq) SizeBytes() int {
	return u.DirFD.SizeBytes() + u.Flags.SizeBytes() + u.Name.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UnlinkAtReq) MarshalBytes(dst []byte) []byte {
	dst = u.DirFD.MarshalUnsafe(dst)
	dst = u.Flags.MarshalUnsafe(dst)
	return u.Name.MarshalBytes(dst)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (u *UnlinkAtReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	u.Name = ""
	if u.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := u.DirFD.UnmarshalUnsafe(src)
	srcRemain = u.Flags.UnmarshalUnsafe(srcRemain)
	if srcRemain, ok := u.Name.CheckedUnmarshal(srcRemain); ok {
		return srcRemain, true
	}
	return src, false
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (r *RenameAtReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	r.NewName = ""
	if r.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := r.Renamed.UnmarshalUnsafe(src)
	srcRemain = r.NewDir.UnmarshalUnsafe(srcRemain)
	if srcRemain, ok := r.NewName.CheckedUnmarshal(srcRemain); ok {
		return srcRemain, true
	}
	return src, false
}

// Getdents64Req is used to make Getdents64 requests.
//
// +marshal boundCheck
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (d *Dirent64) CheckedUnmarshal(src []byte) ([]byte, bool) {
	d.Name = ""
	if d.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := d.Ino.UnmarshalUnsafe(src)
	srcRemain = d.DevMinor.UnmarshalUnsafe(srcRemain)
	srcRemain = d.DevMajor.UnmarshalUnsafe(srcRemain)
	srcRemain = d.Off.UnmarshalUnsafe(srcRemain)
	srcRemain = d.Type.UnmarshalUnsafe(srcRemain)
	if srcRemain, ok := d.Name.CheckedUnmarshal(srcRemain); ok {
		return srcRemain, true
	}
	return src, false
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (g *Getdents64Resp) CheckedUnmarshal(src []byte) ([]byte, bool) {
	g.Dirents = g.Dirents[:0]
	if g.SizeBytes() > len(src) {
		return src, false
	}
	var numDirents primitive.Uint32
	srcRemain := numDirents.UnmarshalUnsafe(src)
	if cap(g.Dirents) < int(numDirents) {
		g.Dirents = make([]Dirent64, numDirents)
	} else {
		g.Dirents = g.Dirents[:numDirents]
	}

	var ok bool
	for i := range g.Dirents {
		if srcRemain, ok = g.Dirents[i].CheckedUnmarshal(srcRemain); !ok {
			return src, false
		}
	}
	return srcRemain, true
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (g *FGetXattrReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	g.Name = ""
	if g.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := g.FD.UnmarshalUnsafe(src)
	srcRemain = g.BufSize.UnmarshalUnsafe(srcRemain)
	if srcRemain, ok := g.Name.CheckedUnmarshal(srcRemain); ok {
		return srcRemain, true
	}
	return src, false
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (g *FGetXattrResp) CheckedUnmarshal(src []byte) ([]byte, bool) {
	return g.Value.CheckedUnmarshal(src)
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (s *FSetXattrReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	s.Name = ""
	s.Value = ""
	if s.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := s.FD.UnmarshalUnsafe(src)
	srcRemain = s.Flags.UnmarshalUnsafe(srcRemain)
	var ok bool
	if srcRemain, ok = s.Name.CheckedUnmarshal(srcRemain); !ok {
		return src, false
	}
	if srcRemain, ok = s.Value.CheckedUnmarshal(srcRemain); !ok {
		return src, false
	}
	return srcRemain, true
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (r *FRemoveXattrReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	r.Name = ""
	if r.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := r.FD.UnmarshalUnsafe(src)
	if srcRemain, ok := r.Name.CheckedUnmarshal(srcRemain); ok {
		return srcRemain, true
	}
	return src, false
}

// FListXattrReq is used to make FListXattr requests.
//
// +marshal boundCheck
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

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (l *FListXattrResp) CheckedUnmarshal(src []byte) ([]byte, bool) {
	return l.Xattrs.CheckedUnmarshal(src)
}
