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

// Package p9 used a 9P2000.L implementation. It served its purpose well,
// but has been replaced by LisaFS.
//
// All that remains are some types that are used in LisaFS.
package p9

import (
	"fmt"
	"math"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// OpenFlags is the mode passed to Open and Create operations.
//
// These correspond to bits sent over the wire.
type OpenFlags uint32

const (
	// ReadOnly is a Tlopen and Tlcreate flag indicating read-only mode.
	ReadOnly OpenFlags = 0

	// WriteOnly is a Tlopen and Tlcreate flag indicating write-only mode.
	WriteOnly OpenFlags = 1

	// ReadWrite is a Tlopen flag indicates read-write mode.
	ReadWrite OpenFlags = 2

	// OpenFlagsModeMask is a mask of valid OpenFlags mode bits.
	OpenFlagsModeMask OpenFlags = 3

	// OpenTruncate is a Tlopen flag indicating that the opened file should be
	// truncated.
	OpenTruncate OpenFlags = 01000
)

// SocketType is the socket type passed in Connect and Bind operations.
//
// These correspond to bits sent over the wire.
type SocketType uint32

const (
	// StreamSocket indicates SOCK_STREAM mode.
	StreamSocket SocketType = 0

	// DgramSocket indicates SOCK_DGRAM mode.
	DgramSocket SocketType = 1

	// SeqpacketSocket indicates SOCK_SEQPACKET mode.
	SeqpacketSocket SocketType = 2

	// AnonymousSocket is only valid for Connect calls, and indicates that
	// the caller will accept any socket type.
	AnonymousSocket SocketType = 3
)

// ToLinux maps the SocketType to a Linux socket type.
func (st SocketType) ToLinux() (linux.SockType, bool) {
	switch st {
	case StreamSocket:
		return linux.SOCK_STREAM, true
	case DgramSocket:
		return linux.SOCK_DGRAM, true
	case SeqpacketSocket:
		return linux.SOCK_SEQPACKET, true
	default:
		return 0, false
	}
}

// SocketTypeFromLinux maps a Linux socket type to a SocketType.
func SocketTypeFromLinux(st linux.SockType) (SocketType, bool) {
	switch st {
	case linux.SOCK_STREAM:
		return StreamSocket, true
	case linux.SOCK_DGRAM:
		return DgramSocket, true
	case linux.SOCK_SEQPACKET:
		return SeqpacketSocket, true
	default:
		return 0, false
	}
}

// OSFlags converts a p9.OpenFlags to an int compatible with open(2).
func (o OpenFlags) OSFlags() int {
	// "flags contains Linux open(2) flags bits" - 9P2000.L
	return int(o)
}

// String implements fmt.Stringer.
func (o OpenFlags) String() string {
	var buf strings.Builder
	switch mode := o & OpenFlagsModeMask; mode {
	case ReadOnly:
		buf.WriteString("ReadOnly")
	case WriteOnly:
		buf.WriteString("WriteOnly")
	case ReadWrite:
		buf.WriteString("ReadWrite")
	default:
		fmt.Fprintf(&buf, "%#o", mode)
	}
	otherFlags := o &^ OpenFlagsModeMask
	if otherFlags&OpenTruncate != 0 {
		buf.WriteString("|OpenTruncate")
		otherFlags &^= OpenTruncate
	}
	if otherFlags != 0 {
		fmt.Fprintf(&buf, "|%#o", otherFlags)
	}
	return buf.String()
}

// FileMode are flags corresponding to file modes.
//
// These correspond to bits sent over the wire.
// These also correspond to mode_t bits.
type FileMode uint32

const (
	// FileModeMask is a mask of all the file mode bits of FileMode.
	FileModeMask FileMode = 0170000

	// ModeSocket is an (unused) mode bit for a socket.
	ModeSocket FileMode = 0140000

	// ModeSymlink is a mode bit for a symlink.
	ModeSymlink FileMode = 0120000

	// ModeRegular is a mode bit for regular files.
	ModeRegular FileMode = 0100000

	// ModeBlockDevice is a mode bit for block devices.
	ModeBlockDevice FileMode = 060000

	// ModeDirectory is a mode bit for directories.
	ModeDirectory FileMode = 040000

	// ModeCharacterDevice is a mode bit for a character device.
	ModeCharacterDevice FileMode = 020000

	// ModeNamedPipe is a mode bit for a named pipe.
	ModeNamedPipe FileMode = 010000

	// Read is a mode bit indicating read permission.
	Read FileMode = 04

	// Write is a mode bit indicating write permission.
	Write FileMode = 02

	// Exec is a mode bit indicating exec permission.
	Exec FileMode = 01

	// AllPermissions is a mask with rwx bits set for user, group and others.
	AllPermissions FileMode = 0777

	// Sticky is a mode bit indicating sticky directories.
	Sticky FileMode = 01000

	// SetGID is the set group ID bit.
	SetGID FileMode = 02000

	// SetUID is the set user ID bit.
	SetUID FileMode = 04000

	// permissionsMask is the mask to apply to FileModes for permissions. It
	// includes rwx bits for user, group, and others, as well as the sticky
	// bit, setuid bit, and setgid bit.
	permissionsMask FileMode = 07777
)

// FileType returns the file mode without the permission bits.
func (m FileMode) FileType() FileMode {
	return m & FileModeMask
}

// Permissions returns just the permission bits of the mode.
func (m FileMode) Permissions() FileMode {
	return m & permissionsMask
}

// Writable returns the mode with write bits added.
func (m FileMode) Writable() FileMode {
	return m | 0222
}

// IsReadable returns true if m represents a file that can be read.
func (m FileMode) IsReadable() bool {
	return m&0444 != 0
}

// IsWritable returns true if m represents a file that can be written to.
func (m FileMode) IsWritable() bool {
	return m&0222 != 0
}

// IsExecutable returns true if m represents a file that can be executed.
func (m FileMode) IsExecutable() bool {
	return m&0111 != 0
}

// IsRegular returns true if m is a regular file.
func (m FileMode) IsRegular() bool {
	return m&FileModeMask == ModeRegular
}

// IsDir returns true if m represents a directory.
func (m FileMode) IsDir() bool {
	return m&FileModeMask == ModeDirectory
}

// IsNamedPipe returns true if m represents a named pipe.
func (m FileMode) IsNamedPipe() bool {
	return m&FileModeMask == ModeNamedPipe
}

// IsCharacterDevice returns true if m represents a character device.
func (m FileMode) IsCharacterDevice() bool {
	return m&FileModeMask == ModeCharacterDevice
}

// IsBlockDevice returns true if m represents a character device.
func (m FileMode) IsBlockDevice() bool {
	return m&FileModeMask == ModeBlockDevice
}

// IsSocket returns true if m represents a socket.
func (m FileMode) IsSocket() bool {
	return m&FileModeMask == ModeSocket
}

// IsSymlink returns true if m represents a symlink.
func (m FileMode) IsSymlink() bool {
	return m&FileModeMask == ModeSymlink
}

// ModeFromOS returns a FileMode from an os.FileMode.
func ModeFromOS(mode os.FileMode) FileMode {
	m := FileMode(mode.Perm())
	switch {
	case mode.IsDir():
		m |= ModeDirectory
	case mode&os.ModeSymlink != 0:
		m |= ModeSymlink
	case mode&os.ModeSocket != 0:
		m |= ModeSocket
	case mode&os.ModeNamedPipe != 0:
		m |= ModeNamedPipe
	case mode&os.ModeCharDevice != 0:
		m |= ModeCharacterDevice
	case mode&os.ModeDevice != 0:
		m |= ModeBlockDevice
	default:
		m |= ModeRegular
	}
	return m
}

// OSMode converts a p9.FileMode to an os.FileMode.
func (m FileMode) OSMode() os.FileMode {
	var osMode os.FileMode
	osMode |= os.FileMode(m.Permissions())
	switch {
	case m.IsDir():
		osMode |= os.ModeDir
	case m.IsSymlink():
		osMode |= os.ModeSymlink
	case m.IsSocket():
		osMode |= os.ModeSocket
	case m.IsNamedPipe():
		osMode |= os.ModeNamedPipe
	case m.IsCharacterDevice():
		osMode |= os.ModeCharDevice | os.ModeDevice
	case m.IsBlockDevice():
		osMode |= os.ModeDevice
	}
	return osMode
}

// UID represents a user ID.
type UID uint32

// Ok returns true if uid is not NoUID.
func (uid UID) Ok() bool {
	return uid != NoUID
}

// GID represents a group ID.
type GID uint32

// Ok returns true if gid is not NoGID.
func (gid GID) Ok() bool {
	return gid != NoGID
}

const (
	// NoUID is a sentinel used to indicate no valid UID.
	NoUID UID = math.MaxUint32

	// NoGID is a sentinel used to indicate no valid GID.
	NoGID GID = math.MaxUint32
)

// FSStat is used by statfs.
type FSStat struct {
	// Type is the filesystem type.
	Type uint32

	// BlockSize is the blocksize.
	BlockSize uint32

	// Blocks is the number of blocks.
	Blocks uint64

	// BlocksFree is the number of free blocks.
	BlocksFree uint64

	// BlocksAvailable is the number of blocks *available*.
	BlocksAvailable uint64

	// Files is the number of files available.
	Files uint64

	// FilesFree is the number of free file nodes.
	FilesFree uint64

	// FSID is the filesystem ID.
	FSID uint64

	// NameLength is the maximum name length.
	NameLength uint32
}

// AttrMask is a mask of attributes for getattr.
type AttrMask struct {
	Mode        bool
	NLink       bool
	UID         bool
	GID         bool
	RDev        bool
	ATime       bool
	MTime       bool
	CTime       bool
	INo         bool
	Size        bool
	Blocks      bool
	BTime       bool
	Gen         bool
	DataVersion bool
}

// Contains returns true if a contains all of the attributes masked as b.
func (a AttrMask) Contains(b AttrMask) bool {
	if b.Mode && !a.Mode {
		return false
	}
	if b.NLink && !a.NLink {
		return false
	}
	if b.UID && !a.UID {
		return false
	}
	if b.GID && !a.GID {
		return false
	}
	if b.RDev && !a.RDev {
		return false
	}
	if b.ATime && !a.ATime {
		return false
	}
	if b.MTime && !a.MTime {
		return false
	}
	if b.CTime && !a.CTime {
		return false
	}
	if b.INo && !a.INo {
		return false
	}
	if b.Size && !a.Size {
		return false
	}
	if b.Blocks && !a.Blocks {
		return false
	}
	if b.BTime && !a.BTime {
		return false
	}
	if b.Gen && !a.Gen {
		return false
	}
	if b.DataVersion && !a.DataVersion {
		return false
	}
	return true
}

// Empty returns true if no fields are masked.
func (a AttrMask) Empty() bool {
	return !a.Mode && !a.NLink && !a.UID && !a.GID && !a.RDev && !a.ATime && !a.MTime && !a.CTime && !a.INo && !a.Size && !a.Blocks && !a.BTime && !a.Gen && !a.DataVersion
}

// AttrMaskAll returns an AttrMask with all fields masked.
func AttrMaskAll() AttrMask {
	return AttrMask{
		Mode:        true,
		NLink:       true,
		UID:         true,
		GID:         true,
		RDev:        true,
		ATime:       true,
		MTime:       true,
		CTime:       true,
		INo:         true,
		Size:        true,
		Blocks:      true,
		BTime:       true,
		Gen:         true,
		DataVersion: true,
	}
}

// String implements fmt.Stringer.
func (a AttrMask) String() string {
	var masks []string
	if a.Mode {
		masks = append(masks, "Mode")
	}
	if a.NLink {
		masks = append(masks, "NLink")
	}
	if a.UID {
		masks = append(masks, "UID")
	}
	if a.GID {
		masks = append(masks, "GID")
	}
	if a.RDev {
		masks = append(masks, "RDev")
	}
	if a.ATime {
		masks = append(masks, "ATime")
	}
	if a.MTime {
		masks = append(masks, "MTime")
	}
	if a.CTime {
		masks = append(masks, "CTime")
	}
	if a.INo {
		masks = append(masks, "INo")
	}
	if a.Size {
		masks = append(masks, "Size")
	}
	if a.Blocks {
		masks = append(masks, "Blocks")
	}
	if a.BTime {
		masks = append(masks, "BTime")
	}
	if a.Gen {
		masks = append(masks, "Gen")
	}
	if a.DataVersion {
		masks = append(masks, "DataVersion")
	}
	return fmt.Sprintf("AttrMask{with: %s}", strings.Join(masks, " "))
}

// Attr is a set of attributes for getattr.
type Attr struct {
	Mode             FileMode
	UID              UID
	GID              GID
	NLink            uint64
	RDev             uint64
	Size             uint64
	BlockSize        uint64
	Blocks           uint64
	ATimeSeconds     uint64
	ATimeNanoSeconds uint64
	MTimeSeconds     uint64
	MTimeNanoSeconds uint64
	CTimeSeconds     uint64
	CTimeNanoSeconds uint64
	BTimeSeconds     uint64
	BTimeNanoSeconds uint64
	Gen              uint64
	DataVersion      uint64
}

// String implements fmt.Stringer.
func (a Attr) String() string {
	return fmt.Sprintf("Attr{Mode: 0o%o, UID: %d, GID: %d, NLink: %d, RDev: %d, Size: %d, BlockSize: %d, Blocks: %d, ATime: {Sec: %d, NanoSec: %d}, MTime: {Sec: %d, NanoSec: %d}, CTime: {Sec: %d, NanoSec: %d}, BTime: {Sec: %d, NanoSec: %d}, Gen: %d, DataVersion: %d}",
		a.Mode, a.UID, a.GID, a.NLink, a.RDev, a.Size, a.BlockSize, a.Blocks, a.ATimeSeconds, a.ATimeNanoSeconds, a.MTimeSeconds, a.MTimeNanoSeconds, a.CTimeSeconds, a.CTimeNanoSeconds, a.BTimeSeconds, a.BTimeNanoSeconds, a.Gen, a.DataVersion)
}

// StatToAttr converts a Linux syscall stat structure to an Attr.
func StatToAttr(s *syscall.Stat_t, req AttrMask) (Attr, AttrMask) {
	attr := Attr{
		UID: NoUID,
		GID: NoGID,
	}
	if req.Mode {
		// p9.FileMode corresponds to Linux mode_t.
		attr.Mode = FileMode(s.Mode)
	}
	if req.NLink {
		attr.NLink = uint64(s.Nlink)
	}
	if req.UID {
		attr.UID = UID(s.Uid)
	}
	if req.GID {
		attr.GID = GID(s.Gid)
	}
	if req.RDev {
		attr.RDev = s.Dev
	}
	if req.ATime {
		attr.ATimeSeconds = uint64(s.Atim.Sec)
		attr.ATimeNanoSeconds = uint64(s.Atim.Nsec)
	}
	if req.MTime {
		attr.MTimeSeconds = uint64(s.Mtim.Sec)
		attr.MTimeNanoSeconds = uint64(s.Mtim.Nsec)
	}
	if req.CTime {
		attr.CTimeSeconds = uint64(s.Ctim.Sec)
		attr.CTimeNanoSeconds = uint64(s.Ctim.Nsec)
	}
	if req.Size {
		attr.Size = uint64(s.Size)
	}
	if req.Blocks {
		attr.BlockSize = uint64(s.Blksize)
		attr.Blocks = uint64(s.Blocks)
	}

	// Use the req field because we already have it.
	req.BTime = false
	req.Gen = false
	req.DataVersion = false

	return attr, req
}

// AllocateMode are possible modes to p9.File.Allocate().
type AllocateMode struct {
	KeepSize      bool
	PunchHole     bool
	NoHideStale   bool
	CollapseRange bool
	ZeroRange     bool
	InsertRange   bool
	Unshare       bool
}

// ToAllocateMode returns an AllocateMode from a fallocate(2) mode.
func ToAllocateMode(mode uint64) AllocateMode {
	return AllocateMode{
		KeepSize:      mode&unix.FALLOC_FL_KEEP_SIZE != 0,
		PunchHole:     mode&unix.FALLOC_FL_PUNCH_HOLE != 0,
		NoHideStale:   mode&unix.FALLOC_FL_NO_HIDE_STALE != 0,
		CollapseRange: mode&unix.FALLOC_FL_COLLAPSE_RANGE != 0,
		ZeroRange:     mode&unix.FALLOC_FL_ZERO_RANGE != 0,
		InsertRange:   mode&unix.FALLOC_FL_INSERT_RANGE != 0,
		Unshare:       mode&unix.FALLOC_FL_UNSHARE_RANGE != 0,
	}
}

// ToLinux converts to a value compatible with fallocate(2)'s mode.
func (a *AllocateMode) ToLinux() uint32 {
	rv := uint32(0)
	if a.KeepSize {
		rv |= unix.FALLOC_FL_KEEP_SIZE
	}
	if a.PunchHole {
		rv |= unix.FALLOC_FL_PUNCH_HOLE
	}
	if a.NoHideStale {
		rv |= unix.FALLOC_FL_NO_HIDE_STALE
	}
	if a.CollapseRange {
		rv |= unix.FALLOC_FL_COLLAPSE_RANGE
	}
	if a.ZeroRange {
		rv |= unix.FALLOC_FL_ZERO_RANGE
	}
	if a.InsertRange {
		rv |= unix.FALLOC_FL_INSERT_RANGE
	}
	if a.Unshare {
		rv |= unix.FALLOC_FL_UNSHARE_RANGE
	}
	return rv
}
