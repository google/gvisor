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
	"os"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// Messages have two parts:
//  * A transport header used to decipher received messages.
//  * A byte array referred to as "payload" which contains the actual message.
// "dataLen" refers to the size of both combined.
//
// All messages must implement the following functions:
//	* marshal.Marshallable.SizeBytes
//	* marshal.Marshallable.Marshal{Unsafe/Bytes}
//	* marshal.CheckedMarshallable.CheckedUnmarshal
//	* fmt.Stringer.String
//
// There is no explicit interface definition for this because that definition
// will not be used anywhere. If a concrete type is passed into a function
// which receives it as an interface, the struct is moved to the heap. This
// erodes memory performance. Message structs are be short lived - they are
// initialized, marshalled into a buffer and not used after that. So heap
// allocating these message structs is wasteful. Don't define Message interface
// so it's not used. Instead use function arguments. See Client.SndRcvMessage.
//
// Unmarshalling code should use the Checked variant of the Unmarshal functions
// because a malicious encoder could have manipulated payload bytes to make the
// unchecked unmarshal variants panic due to the lack of bound checking.
// Marshalling code does not need additional bound checking because the caller
// itself intializes the struct being marshalled, so it is trusted.
//
// String() implementations must ensure that the message struct doesn't escape.
// For instance, directly passing the struct to fmt.Sprintf() escapes it
// because of the implicit conversion to any.

type marshalFunc func([]byte) []byte
type unmarshalFunc func([]byte) ([]byte, bool)
type debugStringer func() string

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

	// BindAt is analogous to bind(2).
	BindAt MID = 29

	// Listen is analogous to listen(2).
	Listen MID = 30

	// Accept is analogous to accept4(2).
	Accept MID = 31
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

// EmptyMessage is an empty message.
type EmptyMessage struct{}

// String implements fmt.Stringer.String.
func (*EmptyMessage) String() string {
	return "EmptyMessage{}"
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (*EmptyMessage) SizeBytes() int {
	return 0
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (*EmptyMessage) MarshalBytes(dst []byte) []byte { return dst }

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (*EmptyMessage) CheckedUnmarshal(src []byte) ([]byte, bool) { return src, true }

// SizedString represents a string in memory. The marshalled string bytes are
// preceded by a uint16 signifying the string length.
type SizedString string

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SizedString) SizeBytes() int {
	return (*primitive.Uint16)(nil).SizeBytes() + len(*s)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SizedString) MarshalBytes(dst []byte) []byte {
	strLen := primitive.Uint16(len(*s))
	dst = strLen.MarshalUnsafe(dst)
	// Copy without any allocation.
	return dst[copy(dst[:strLen], *s):]
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (s *SizedString) CheckedUnmarshal(src []byte) ([]byte, bool) {
	var strLen primitive.Uint16
	srcRemain, ok := strLen.CheckedUnmarshal(src)
	if !ok || len(srcRemain) < int(strLen) {
		return src, false
	}
	// Take the hit, this leads to an allocation + memcpy. No way around it.
	*s = SizedString(srcRemain[:strLen])
	return srcRemain[strLen:], true
}

// StringArray represents an array of SizedStrings in memory. The marshalled
// array data is preceded by a uint16 signifying the array length.
type StringArray []string

// String implements fmt.Stringer.String. This ensures that the string slice is
// not escaped so that callers that use a statically sized string array do not
// incur an unnecessary allocation.
func (s *StringArray) String() string {
	var b strings.Builder
	b.WriteString("[")
	for _, str := range *s {
		b.WriteString(fmt.Sprintf("%s, ", str))
	}
	b.WriteString("]")
	return b.String()
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *StringArray) SizeBytes() int {
	size := (*primitive.Uint16)(nil).SizeBytes()
	for _, str := range *s {
		sstr := SizedString(str)
		size += sstr.SizeBytes()
	}
	return size
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *StringArray) MarshalBytes(dst []byte) []byte {
	arrLen := primitive.Uint16(len(*s))
	dst = arrLen.MarshalUnsafe(dst)
	for _, str := range *s {
		sstr := SizedString(str)
		dst = sstr.MarshalBytes(dst)
	}
	return dst
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (s *StringArray) CheckedUnmarshal(src []byte) ([]byte, bool) {
	var arrLen primitive.Uint16
	srcRemain, ok := arrLen.CheckedUnmarshal(src)
	if !ok {
		return src, false
	}

	if cap(*s) < int(arrLen) {
		*s = make([]string, arrLen)
	} else {
		*s = (*s)[:arrLen]
	}

	for i := primitive.Uint16(0); i < arrLen; i++ {
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
	Stat      linux.Statx
}

// MountReq is an empty requent to Mount on the connection.
type MountReq struct{ EmptyMessage }

// String implements fmt.Stringer.String.
func (*MountReq) String() string {
	return "MountReq{}"
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

// String implements fmt.Stringer.String.
func (m *MountResp) String() string {
	return fmt.Sprintf("MountResp{Root: %+v, MaxMessageSize: %d, SupportedMs: %+v}", m.Root, m.MaxMessageSize, m.SupportedMs)
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

// ChannelReq is an empty requent to create a Channel.
type ChannelReq struct{ EmptyMessage }

// String implements fmt.Stringer.String.
func (*ChannelReq) String() string {
	return "ChannelReq{}"
}

// ChannelResp is the response to the create channel request.
//
// +marshal boundCheck
type ChannelResp struct {
	dataOffset int64
	dataLength uint64
}

// String implements fmt.Stringer.String.
func (c *ChannelResp) String() string {
	return fmt.Sprintf("ChannelResp{dataOffset: %d, dataLength: %d}", c.dataOffset, c.dataLength)
}

// ErrorResp is returned to represent an error while handling a request.
//
// +marshal
type ErrorResp struct {
	errno uint32
}

// String implements fmt.Stringer.String.
func (e *ErrorResp) String() string {
	return fmt.Sprintf("ErrorResp{errno: %d}", e.errno)
}

// StatReq requests the stat results for the specified FD.
//
// +marshal boundCheck
type StatReq struct {
	FD FDID
}

// String implements fmt.Stringer.String.
func (s *StatReq) String() string {
	return fmt.Sprintf("StatReq{FD: %d}", s.FD)
}

// SetStatReq is used to set attributeds on FDs.
//
// +marshal boundCheck
type SetStatReq struct {
	FD    FDID
	Mask  uint32
	Mode  uint32 // Only permissions part is settable.
	UID   UID
	GID   GID
	Size  uint64
	Atime linux.Timespec
	Mtime linux.Timespec
}

// String implements fmt.Stringer.String.
func (s *SetStatReq) String() string {
	return fmt.Sprintf("SetStatReq{FD: %d, Mask: %d, Mode: %d, UID: %d, GID: %d, Size: %d, Atime: %+v, Mtime: %+v}",
		s.FD, s.Mask, s.Mode, s.UID, s.GID, s.Size, s.Atime, s.Mtime)
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

// String implements fmt.Stringer.String.
func (s *SetStatResp) String() string {
	return fmt.Sprintf("SetStatResp{FailureMask: %d, FailureErrNo: %d}", s.FailureMask, s.FailureErrNo)
}

// WalkReq is used to request to walk multiple path components at once. This
// is used for both Walk and WalkStat.
type WalkReq struct {
	DirFD FDID
	Path  StringArray
}

// String implements fmt.Stringer.String.
func (w *WalkReq) String() string {
	return fmt.Sprintf("WalkReq{DirFD: %d, Path: %s}", w.DirFD, w.Path.String())
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

// WalkResp is used to communicate the inodes walked by the server. In memory,
// the inode array is preceded by a uint16 integer denoting array length.
type WalkResp struct {
	Status WalkStatus
	Inodes []Inode
}

// String implements fmt.Stringer.String. This ensures that the Inode slice is
// not escaped so that callers that use a statically sized Inode array do not
// incur an unnecessary allocation.
func (w *WalkResp) String() string {
	var arrB strings.Builder
	arrB.WriteString("[")
	for i := range w.Inodes {
		arrB.WriteString(fmt.Sprintf("%+v, ", w.Inodes[i]))
	}
	arrB.WriteString("]")
	return fmt.Sprintf("WalkResp{Status: %d, Inodes: %s}", w.Status, arrB.String())
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (w *WalkResp) SizeBytes() int {
	return w.Status.SizeBytes() +
		(*primitive.Uint16)(nil).SizeBytes() + (len(w.Inodes) * (*Inode)(nil).SizeBytes())
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (w *WalkResp) MarshalBytes(dst []byte) []byte {
	dst = w.Status.MarshalUnsafe(dst)

	numInodes := primitive.Uint16(len(w.Inodes))
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

	var numInodes primitive.Uint16
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

// WalkStatResp is used to communicate stat results for WalkStat. In memory,
// the array data is preceded by a uint16 denoting the array length.
type WalkStatResp struct {
	Stats []linux.Statx
}

// String implements fmt.Stringer.String.
func (w *WalkStatResp) String() string {
	return fmt.Sprintf("WalkStatResp{Stats: %+v}", w.Stats)
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (w *WalkStatResp) SizeBytes() int {
	return (*primitive.Uint16)(nil).SizeBytes() + (len(w.Stats) * linux.SizeOfStatx)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (w *WalkStatResp) MarshalBytes(dst []byte) []byte {
	numStats := primitive.Uint16(len(w.Stats))
	dst = numStats.MarshalUnsafe(dst)

	return linux.MarshalUnsafeStatxSlice(w.Stats, dst)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (w *WalkStatResp) CheckedUnmarshal(src []byte) ([]byte, bool) {
	w.Stats = w.Stats[:0]
	if w.SizeBytes() > len(src) {
		return src, false
	}
	var numStats primitive.Uint16
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
	_     uint32 // Need to make struct packed.
}

// String implements fmt.Stringer.String.
func (o *OpenAtReq) String() string {
	return fmt.Sprintf("OpenAtReq{FD: %d, Flags: %d}", o.FD, o.Flags)
}

// OpenAtResp is used to communicate the newly created FD.
//
// +marshal boundCheck
type OpenAtResp struct {
	OpenFD FDID
}

// String implements fmt.Stringer.String.
func (o *OpenAtResp) String() string {
	return fmt.Sprintf("OpenAtResp{OpenFD: %d}", o.OpenFD)
}

// +marshal
type createCommon struct {
	DirFD FDID
	UID   UID
	GID   GID
	Mode  linux.FileMode
	// The following are needed to make the struct packed.
	_ uint16
	_ uint32
}

// OpenCreateAtReq is used to make OpenCreateAt requests.
type OpenCreateAtReq struct {
	createCommon
	Flags primitive.Uint32
	Name  SizedString
}

// String implements fmt.Stringer.String.
func (o *OpenCreateAtReq) String() string {
	return fmt.Sprintf("OpenCreateAtReq{DirFD: %d, Mode: %s, UID: %d, GID: %d, Flags: %d, Name: %s}", o.DirFD, o.Mode, o.UID, o.GID, o.Flags, o.Name)
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
}

// String implements fmt.Stringer.String.
func (o *OpenCreateAtResp) String() string {
	return fmt.Sprintf("OpenCreateAtResp{Child: %+v, NewFD: %d}", o.Child, o.NewFD)
}

// FdArray is a utility struct which implements a marshallable type for
// communicating an array of FDIDs. In memory, the array data is preceded by a
// uint16 denoting the array length.
type FdArray []FDID

// String implements fmt.Stringer.String. This ensures that the FDID slice is
// not escaped so that callers that use a statically sized FDID array do not
// incur an unnecessary allocation.
func (f *FdArray) String() string {
	var b strings.Builder
	b.WriteString("[")
	for _, fd := range *f {
		b.WriteString(fmt.Sprintf("%d, ", fd))
	}
	b.WriteString("]")
	return b.String()
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FdArray) SizeBytes() int {
	return (*primitive.Uint16)(nil).SizeBytes() + (len(*f) * (*FDID)(nil).SizeBytes())
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FdArray) MarshalBytes(dst []byte) []byte {
	arrLen := primitive.Uint16(len(*f))
	dst = arrLen.MarshalUnsafe(dst)
	return MarshalUnsafeFDIDSlice(*f, dst)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (f *FdArray) CheckedUnmarshal(src []byte) ([]byte, bool) {
	*f = (*f)[:0]
	if f.SizeBytes() > len(src) {
		return src, false
	}
	var arrLen primitive.Uint16
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

// String implements fmt.Stringer.String.
func (c *CloseReq) String() string {
	return fmt.Sprintf("CloseReq{FDs: %s}", c.FDs.String())
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

// CloseResp is an empty response to CloseReq.
type CloseResp struct{ EmptyMessage }

// String implements fmt.Stringer.String.
func (*CloseResp) String() string {
	return "CloseResp{}"
}

// FsyncReq is used to fsync(2) FDs.
type FsyncReq struct {
	FDs FdArray
}

// String implements fmt.Stringer.String.
func (f *FsyncReq) String() string {
	return fmt.Sprintf("FsyncReq{FDs: %s}", f.FDs.String())
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

// FsyncResp is an empty response to FsyncReq.
type FsyncResp struct{ EmptyMessage }

// String implements fmt.Stringer.String.
func (*FsyncResp) String() string {
	return "FsyncResp{}"
}

// PReadReq is used to pread(2) on an FD.
//
// +marshal boundCheck
type PReadReq struct {
	Offset uint64
	FD     FDID
	Count  uint32
	_      uint32 // Need to make struct packed.
}

// String implements fmt.Stringer.String.
func (r *PReadReq) String() string {
	return fmt.Sprintf("PReadReq{Offset: %d, FD: %d, Count: %d}", r.Offset, r.FD, r.Count)
}

// PReadResp is used to return the result of pread(2).
type PReadResp struct {
	NumBytes primitive.Uint64
	Buf      []byte
}

// String implements fmt.Stringer.String.
func (r *PReadResp) String() string {
	return fmt.Sprintf("PReadResp{NumBytes: %d, Buf: [...%d bytes...]}", r.NumBytes, len(r.Buf))
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
	if !ok || uint32(r.NumBytes) > uint32(len(srcRemain)) || uint32(r.NumBytes) > uint32(len(r.Buf)) {
		return src, false
	}

	// We expect the client to have already allocated r.Buf. r.Buf probably
	// (optimally) points to usermem. Directly copy into that.
	r.Buf = r.Buf[:r.NumBytes]
	return srcRemain[copy(r.Buf, srcRemain[:r.NumBytes]):], true
}

// PWriteReq is used to pwrite(2) on an FD.
type PWriteReq struct {
	Offset   primitive.Uint64
	FD       FDID
	NumBytes primitive.Uint32
	Buf      []byte
}

// String implements fmt.Stringer.String.
func (w *PWriteReq) String() string {
	return fmt.Sprintf("PWriteReq{Offset: %d, FD: %d, NumBytes: %d, Buf: [...%d bytes...]}", w.Offset, w.FD, w.NumBytes, len(w.Buf))
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
	if uint32(w.NumBytes) > uint32(len(srcRemain)) {
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

// String implements fmt.Stringer.String.
func (w *PWriteResp) String() string {
	return fmt.Sprintf("PWriteResp{Count: %d}", w.Count)
}

// MkdirAtReq is used to make MkdirAt requests.
type MkdirAtReq struct {
	createCommon
	Name SizedString
}

// String implements fmt.Stringer.String.
func (m *MkdirAtReq) String() string {
	return fmt.Sprintf("MkdirAtReq{DirFD: %d, Mode: %s, UID: %d, GID: %d, Name: %s}", m.DirFD, m.Mode, m.UID, m.GID, m.Name)
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

// String implements fmt.Stringer.String.
func (m *MkdirAtResp) String() string {
	return fmt.Sprintf("MkdirAtResp{ChildDir: %+v}", m.ChildDir)
}

// MknodAtReq is used to make MknodAt requests.
type MknodAtReq struct {
	createCommon
	Minor primitive.Uint32
	Major primitive.Uint32
	Name  SizedString
}

// String implements fmt.Stringer.String.
func (m *MknodAtReq) String() string {
	return fmt.Sprintf("MknodAtReq{DirFD: %d, Mode: %s, UID: %d, GID: %d, Minor: %d, Major: %d, Name: %s}", m.DirFD, m.Mode, m.UID, m.GID, m.Minor, m.Major, m.Name)
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

// String implements fmt.Stringer.String.
func (m *MknodAtResp) String() string {
	return fmt.Sprintf("MknodAtResp{Child: %+v}", m.Child)
}

// SymlinkAtReq is used to make SymlinkAt request.
type SymlinkAtReq struct {
	DirFD  FDID
	UID    UID
	GID    GID
	Name   SizedString
	Target SizedString
}

// String implements fmt.Stringer.String.
func (s *SymlinkAtReq) String() string {
	return fmt.Sprintf("SymlinkAtReq{DirFD: %d, UID: %d, GID: %d, Name: %s, Target: %s}", s.DirFD, s.UID, s.GID, s.Name, s.Target)
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

// String implements fmt.Stringer.String.
func (s *SymlinkAtResp) String() string {
	return fmt.Sprintf("SymlinkAtResp{Symlink: %+v}", s.Symlink)
}

// LinkAtReq is used to make LinkAt requests.
type LinkAtReq struct {
	DirFD  FDID
	Target FDID
	Name   SizedString
}

// String implements fmt.Stringer.String.
func (l *LinkAtReq) String() string {
	return fmt.Sprintf("LinkAtReq{DirFD: %d, Target: %d, Name: %s}", l.DirFD, l.Target, l.Name)
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

// String implements fmt.Stringer.String.
func (l *LinkAtResp) String() string {
	return fmt.Sprintf("LinkAtResp{Link: %+v}", l.Link)
}

// FStatFSReq is used to request StatFS results for the specified FD.
//
// +marshal boundCheck
type FStatFSReq struct {
	FD FDID
}

// String implements fmt.Stringer.String.
func (s *FStatFSReq) String() string {
	return fmt.Sprintf("FStatFSReq{FD: %d}", s.FD)
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

// String implements fmt.Stringer.String.
func (s *StatFS) String() string {
	return fmt.Sprintf("StatFS{Type: %d, BlockSize: %d, Blocks: %d, BlocksFree: %d, BlocksAvailable: %d, Files: %d, FilesFree: %d, NameLength: %d}",
		s.Type, s.BlockSize, s.Blocks, s.BlocksFree, s.BlocksAvailable, s.Files, s.FilesFree, s.NameLength)
}

// FAllocateReq is used to request to fallocate(2) an FD. This has no response.
//
// +marshal boundCheck
type FAllocateReq struct {
	FD     FDID
	Mode   uint64
	Offset uint64
	Length uint64
}

// String implements fmt.Stringer.String.
func (a *FAllocateReq) String() string {
	return fmt.Sprintf("FAllocateReq{FD: %d, Mode: %d, Offset: %d, Length: %d}", a.FD, a.Mode, a.Offset, a.Length)
}

// FAllocateResp is an empty response to FAllocateReq.
type FAllocateResp struct{ EmptyMessage }

// String implements fmt.Stringer.String.
func (*FAllocateResp) String() string {
	return "FAllocateResp{}"
}

// ReadLinkAtReq is used to readlinkat(2) at the specified FD.
//
// +marshal boundCheck
type ReadLinkAtReq struct {
	FD FDID
}

// String implements fmt.Stringer.String.
func (r *ReadLinkAtReq) String() string {
	return fmt.Sprintf("ReadLinkAtReq{FD: %d}", r.FD)
}

// ReadLinkAtResp is used to communicate ReadLinkAt results.
type ReadLinkAtResp struct {
	Target SizedString
}

// String implements fmt.Stringer.String.
func (r *ReadLinkAtResp) String() string {
	return fmt.Sprintf("ReadLinkAtResp{Target: %s}", r.Target)
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

// String implements fmt.Stringer.String.
func (f *FlushReq) String() string {
	return fmt.Sprintf("FlushReq{FD: %d}", f.FD)
}

// FlushResp is an empty response to FlushReq.
type FlushResp struct{ EmptyMessage }

// String implements fmt.Stringer.String.
func (*FlushResp) String() string {
	return "FlushResp{}"
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
	_        uint32 // Need to make struct packed.
}

// String implements fmt.Stringer.String.
func (c *ConnectReq) String() string {
	return fmt.Sprintf("ConnectReq{FD: %d, SockType: %d}", c.FD, c.SockType)
}

// ConnectResp is an empty response to ConnectReq.
type ConnectResp struct{ EmptyMessage }

// String implements fmt.Stringer.String.
func (*ConnectResp) String() string {
	return "ConnectResp{}"
}

// BindAtReq is used to make BindAt requests.
type BindAtReq struct {
	createCommon
	SockType primitive.Uint32
	Name     SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (b *BindAtReq) SizeBytes() int {
	return b.createCommon.SizeBytes() + b.SockType.SizeBytes() + b.Name.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (b *BindAtReq) MarshalBytes(dst []byte) []byte {
	dst = b.createCommon.MarshalUnsafe(dst)
	dst = b.SockType.MarshalUnsafe(dst)
	return b.Name.MarshalBytes(dst)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (b *BindAtReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	b.Name = ""
	if b.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := b.createCommon.UnmarshalUnsafe(src)
	srcRemain = b.SockType.UnmarshalUnsafe(srcRemain)
	if srcRemain, ok := b.Name.CheckedUnmarshal(srcRemain); ok {
		return srcRemain, ok
	}
	return src, false
}

// String implements fmt.Stringer.String.
func (b *BindAtReq) String() string {
	return fmt.Sprintf("BindAtReq{DirFD: %d, Mode: %s, UID: %d, GID: %d, SockType: %d, Name: %q}", b.DirFD, b.Mode, b.UID, b.GID, b.SockType, b.Name)
}

// BindAtResp is used to communicate BindAt response.
//
// +marshal boundCheck
type BindAtResp struct {
	Child         Inode
	BoundSocketFD FDID
}

// String implements fmt.Stringer.String.
func (b *BindAtResp) String() string {
	return fmt.Sprintf("BindAtResp{Child: %+v, BoundSocketFD: %v}", b.Child, b.BoundSocketFD)
}

// ListenReq is used to make Listen requests.
//
// +marshal boundCheck
type ListenReq struct {
	FD      FDID
	Backlog int32
	_       uint32
}

// String implements fmt.Stringer.String.
func (l *ListenReq) String() string {
	return fmt.Sprintf("ListenReq{FD: %v, Backlog: %d}", l.FD, l.Backlog)
}

// ListenResp is an empty response to ListenResp.
type ListenResp struct{ EmptyMessage }

// String implements fmt.Stringer.String.
func (*ListenResp) String() string {
	return "ListenResp{}"
}

// AcceptReq is used to make AcceptRequests.
//
// +marshal boundCheck
type AcceptReq struct {
	FD FDID
}

// String implements fmt.Stringer.String.
func (a *AcceptReq) String() string {
	return fmt.Sprintf("AcceptReq{FD: %v}", a.FD)
}

// AcceptResp is an empty response to AcceptResp.
type AcceptResp struct {
	PeerAddr SizedString
}

// String implements fmt.Stringer.String.
func (a *AcceptResp) String() string {
	return fmt.Sprintf("AcceptResp{PeerAddr: %s}", a.PeerAddr)
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (a *AcceptResp) SizeBytes() int {
	return a.PeerAddr.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (a *AcceptResp) MarshalBytes(dst []byte) []byte {
	return a.PeerAddr.MarshalBytes(dst)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (a *AcceptResp) CheckedUnmarshal(src []byte) ([]byte, bool) {
	return a.PeerAddr.CheckedUnmarshal(src)
}

// UnlinkAtReq is used to make UnlinkAt request.
type UnlinkAtReq struct {
	DirFD FDID
	Flags primitive.Uint32
	Name  SizedString
}

// String implements fmt.Stringer.String.
func (u *UnlinkAtReq) String() string {
	return fmt.Sprintf("UnlinkAtReq{DirFD: %d, Flags: %d, Name: %s}", u.DirFD, u.Flags, u.Name)
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

// UnlinkAtResp is an empty response to UnlinkAtReq.
type UnlinkAtResp struct{ EmptyMessage }

// String implements fmt.Stringer.String.
func (*UnlinkAtResp) String() string {
	return "UnlinkAtResp{}"
}

// RenameAtReq is used to make RenameAt requests. Note that the request takes in
// the to-be-renamed file's FD instead of oldDir and oldName like renameat(2).
type RenameAtReq struct {
	OldDir  FDID
	NewDir  FDID
	OldName SizedString
	NewName SizedString
}

// String implements fmt.Stringer.String.
func (r *RenameAtReq) String() string {
	return fmt.Sprintf("RenameAtReq{OldDir: %d, NewDir: %d, OldName: %s, NewName: %s}", r.OldDir, r.NewDir, r.OldName, r.NewName)
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *RenameAtReq) SizeBytes() int {
	return r.OldDir.SizeBytes() + r.NewDir.SizeBytes() + r.OldName.SizeBytes() + r.NewName.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RenameAtReq) MarshalBytes(dst []byte) []byte {
	dst = r.OldDir.MarshalUnsafe(dst)
	dst = r.NewDir.MarshalUnsafe(dst)
	dst = r.OldName.MarshalBytes(dst)
	return r.NewName.MarshalBytes(dst)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (r *RenameAtReq) CheckedUnmarshal(src []byte) ([]byte, bool) {
	r.OldName = ""
	r.NewName = ""
	if r.SizeBytes() > len(src) {
		return src, false
	}
	srcRemain := r.OldDir.UnmarshalUnsafe(src)
	srcRemain = r.NewDir.UnmarshalUnsafe(srcRemain)
	var ok bool
	if srcRemain, ok = r.OldName.CheckedUnmarshal(srcRemain); !ok {
		return src, false
	}
	if srcRemain, ok = r.NewName.CheckedUnmarshal(srcRemain); !ok {
		return src, false
	}
	return srcRemain, true
}

// RenameAtResp is an empty response to RenameAtReq.
type RenameAtResp struct{ EmptyMessage }

// String implements fmt.Stringer.String.
func (*RenameAtResp) String() string {
	return "RenameAtResp{}"
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
	_     uint32 // Need to make struct packed.
}

// String implements fmt.Stringer.String.
func (g *Getdents64Req) String() string {
	return fmt.Sprintf("Getdents64Req{DirFD: %d, Count: %d}", g.DirFD, g.Count)
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

// String implements fmt.Stringer.String.
func (d *Dirent64) String() string {
	return fmt.Sprintf("Dirent64{Ino: %d, DevMinor: %d, DevMajor: %d, Off: %d, Type: %d, Name: %s}", d.Ino, d.DevMinor, d.DevMajor, d.Off, d.Type, d.Name)
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

// Getdents64Resp is used to communicate getdents64 results. In memory, the
// dirents array is preceded by a uint16 integer denoting array length.
type Getdents64Resp struct {
	Dirents []Dirent64
}

// String implements fmt.Stringer.String.
func (g *Getdents64Resp) String() string {
	return fmt.Sprintf("Getdents64Resp{Dirents: %+v}", g.Dirents)
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (g *Getdents64Resp) SizeBytes() int {
	ret := (*primitive.Uint16)(nil).SizeBytes()
	for i := range g.Dirents {
		ret += g.Dirents[i].SizeBytes()
	}
	return ret
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (g *Getdents64Resp) MarshalBytes(dst []byte) []byte {
	numDirents := primitive.Uint16(len(g.Dirents))
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
	var numDirents primitive.Uint16
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

// String implements fmt.Stringer.String.
func (g *FGetXattrReq) String() string {
	return fmt.Sprintf("FGetXattrReq{FD: %d, BufSize: %d, Name: %s}", g.FD, g.BufSize, g.Name)
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

// String implements fmt.Stringer.String.
func (g *FGetXattrResp) String() string {
	return fmt.Sprintf("FGetXattrResp{Value: %s}", g.Value)
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

// String implements fmt.Stringer.String.
func (s *FSetXattrReq) String() string {
	return fmt.Sprintf("FSetXattrReq{FD: %d, Flags: %d, Name: %s, Value: %s}", s.FD, s.Flags, s.Name, s.Value)
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

// FSetXattrResp is an empty response to FSetXattrReq.
type FSetXattrResp struct{ EmptyMessage }

// String implements fmt.Stringer.String.
func (*FSetXattrResp) String() string {
	return "FSetXattrResp{}"
}

// FRemoveXattrReq is used to make FRemoveXattr requests. It has no response.
type FRemoveXattrReq struct {
	FD   FDID
	Name SizedString
}

// String implements fmt.Stringer.String.
func (r *FRemoveXattrReq) String() string {
	return fmt.Sprintf("FRemoveXattrReq{FD: %d, Name: %s}", r.FD, r.Name)
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

// FRemoveXattrResp is an empty response to FRemoveXattrReq.
type FRemoveXattrResp struct{ EmptyMessage }

// String implements fmt.Stringer.String.
func (*FRemoveXattrResp) String() string {
	return "FRemoveXattrResp{}"
}

// FListXattrReq is used to make FListXattr requests.
//
// +marshal boundCheck
type FListXattrReq struct {
	FD   FDID
	Size uint64
}

// String implements fmt.Stringer.String.
func (l *FListXattrReq) String() string {
	return fmt.Sprintf("FListXattrReq{FD: %d, Size: %d}", l.FD, l.Size)
}

// FListXattrResp is used to respond to FListXattr requests.
type FListXattrResp struct {
	Xattrs StringArray
}

// String implements fmt.Stringer.String.
func (l *FListXattrResp) String() string {
	return fmt.Sprintf("FListXattrResp{Xattrs: %s}", l.Xattrs.String())
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
