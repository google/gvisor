// Copyright 2023 The gVisor Authors.
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

// Package erofs provides the ability to access the contents in an EROFS [1] image.
//
// The design principle of this package is that, it will just provide the ability
// to access the contents in the image, and it will never cache any objects internally.
// The whole disk image is mapped via a read-only/shared mapping, and it relies on
// host kernel to cache the blocks/pages transparently.
//
// [1] https://docs.kernel.org/filesystems/erofs.html
package erofs

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/safemem"
)

const (
	// Definitions for superblock.
	SuperBlockMagicV1 = 0xe0f5e1e2
	SuperBlockOffset  = 1024

	// Inode slot size in bit shift.
	InodeSlotBits = 5

	// Max file name length.
	MaxNameLen = 255
)

// Bit definitions for Inode*::Format.
const (
	InodeLayoutBit  = 0
	InodeLayoutBits = 1

	InodeDataLayoutBit  = 1
	InodeDataLayoutBits = 3
)

// Inode layouts.
const (
	InodeLayoutCompact  = 0
	InodeLayoutExtended = 1
)

// Inode data layouts.
const (
	InodeDataLayoutFlatPlain = iota
	InodeDataLayoutFlatCompressionLegacy
	InodeDataLayoutFlatInline
	InodeDataLayoutFlatCompression
	InodeDataLayoutChunkBased
	InodeDataLayoutMax
)

// Features w/ backward compatibility.
// This is not exhaustive, unused features are not listed.
const (
	FeatureCompatSuperBlockChecksum = 0x00000001
)

// Features w/o backward compatibility.
//
// Any features that aren't in FeatureIncompatSupported are incompatible
// with this implementation.
//
// This is not exhaustive, unused features are not listed.
const (
	FeatureIncompatSupported = 0x0
)

// Sizes of on-disk structures in bytes.
const (
	SuperBlockSize    = 128
	InodeCompactSize  = 32
	InodeExtendedSize = 64
	DirentSize        = 12
)

// SuperBlock represents on-disk superblock.
//
// +marshal
// +stateify savable
type SuperBlock struct {
	Magic           uint32
	Checksum        uint32
	FeatureCompat   uint32
	BlockSizeBits   uint8
	ExtSlots        uint8
	RootNid         uint16
	Inodes          uint64
	BuildTime       uint64
	BuildTimeNsec   uint32
	Blocks          uint32
	MetaBlockAddr   uint32
	XattrBlockAddr  uint32
	UUID            [16]uint8
	VolumeName      [16]uint8
	FeatureIncompat uint32
	Union1          uint16
	ExtraDevices    uint16
	DevTableSlotOff uint16
	Reserved        [38]uint8
}

// BlockSize returns the block size.
func (sb *SuperBlock) BlockSize() uint32 {
	return 1 << sb.BlockSizeBits
}

// BlockAddrToOffset converts block addr to the offset in image file.
func (sb *SuperBlock) BlockAddrToOffset(addr uint32) uint64 {
	return uint64(addr) << sb.BlockSizeBits
}

// MetaOffset returns the offset of metadata area in image file.
func (sb *SuperBlock) MetaOffset() uint64 {
	return sb.BlockAddrToOffset(sb.MetaBlockAddr)
}

// NidToOffset converts inode number to the offset in image file.
func (sb *SuperBlock) NidToOffset(nid uint64) uint64 {
	return sb.MetaOffset() + (nid << InodeSlotBits)
}

// InodeCompact represents 32-byte reduced form of on-disk inode.
//
// +marshal
type InodeCompact struct {
	Format       uint16
	XattrCount   uint16
	Mode         uint16
	Nlink        uint16
	Size         uint32
	Reserved     uint32
	RawBlockAddr uint32
	Ino          uint32
	UID          uint16
	GID          uint16
	Reserved2    uint32
}

// InodeExtended represents 64-byte complete form of on-disk inode.
//
// +marshal
type InodeExtended struct {
	Format       uint16
	XattrCount   uint16
	Mode         uint16
	Reserved     uint16
	Size         uint64
	RawBlockAddr uint32
	Ino          uint32
	UID          uint32
	GID          uint32
	Mtime        uint64
	MtimeNsec    uint32
	Nlink        uint32
	Reserved2    [16]uint8
}

// Dirent represents on-disk directory entry.
//
// +marshal
type Dirent struct {
	NidLow   uint32
	NidHigh  uint32
	NameOff  uint16
	FileType uint8
	Reserved uint8
}

// Nid returns the inode number of the inode referenced by this dirent.
func (d *Dirent) Nid() uint64 {
	// EROFS on-disk structures are always in little endian.
	// TODO: This implementation does not support big endian yet.
	return (uint64(d.NidHigh) << 32) | uint64(d.NidLow)
}

// Image represents an open EROFS image.
//
// +stateify savable
type Image struct {
	src   *os.File `state:"nosave"`
	bytes []byte   `state:"nosave"`
	sb    SuperBlock
}

// OpenImage returns an Image providing access to the contents in the image file src.
//
// On success, the ownership of src is transferred to Image.
func OpenImage(src *os.File) (*Image, error) {
	i := &Image{src: src}

	var cu cleanup.Cleanup
	defer cu.Clean()

	stat, err := i.src.Stat()
	if err != nil {
		return nil, err
	}
	i.bytes, err = unix.Mmap(int(i.src.Fd()), 0, int(stat.Size()), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	cu.Add(func() { unix.Munmap(i.bytes) })

	if err := i.initSuperBlock(); err != nil {
		return nil, err
	}
	cu.Release()
	return i, nil
}

// Close closes the image.
func (i *Image) Close() {
	unix.Munmap(i.bytes)
	i.src.Close()
}

// SuperBlock returns a copy of the image's superblock.
func (i *Image) SuperBlock() SuperBlock {
	return i.sb
}

// BlockSize returns the block size of this image.
func (i *Image) BlockSize() uint32 {
	return i.sb.BlockSize()
}

// Blocks returns the total blocks of this image.
func (i *Image) Blocks() uint32 {
	return i.sb.Blocks
}

// RootNid returns the root inode number of this image.
func (i *Image) RootNid() uint64 {
	return uint64(i.sb.RootNid)
}

// initSuperBlock initializes the superblock of this image.
func (i *Image) initSuperBlock() error {
	// i.sb is used in the hot path. Let's save a copy of the superblock.
	if err := i.unmarshalAt(&i.sb, SuperBlockOffset); err != nil {
		return fmt.Errorf("image size is too small")
	}

	if i.sb.Magic != SuperBlockMagicV1 {
		return fmt.Errorf("unknown magic: 0x%x", i.sb.Magic)
	}

	if err := i.verifyChecksum(); err != nil {
		return err
	}

	if featureIncompat := i.sb.FeatureIncompat & ^uint32(FeatureIncompatSupported); featureIncompat != 0 {
		return fmt.Errorf("unsupported incompatible features detected: 0x%x", featureIncompat)
	}

	if i.BlockSize()%hostarch.PageSize != 0 {
		return fmt.Errorf("unsupported block size: 0x%x", i.BlockSize())
	}

	return nil
}

// verifyChecksum verifies the checksum of the superblock.
func (i *Image) verifyChecksum() error {
	if i.sb.FeatureCompat&FeatureCompatSuperBlockChecksum == 0 {
		return nil
	}

	sb := i.sb
	sb.Checksum = 0
	table := crc32.MakeTable(crc32.Castagnoli)
	checksum := crc32.Checksum(marshal.Marshal(&sb), table)

	off := SuperBlockOffset + uint64(i.sb.SizeBytes())
	if bytes, err := i.BytesAt(off, uint64(i.BlockSize())-off); err != nil {
		return fmt.Errorf("image size is too small")
	} else {
		checksum = ^crc32.Update(checksum, table, bytes)
	}
	if checksum != i.sb.Checksum {
		return fmt.Errorf("invalid checksum: 0x%x, expected: 0x%x", checksum, i.sb.Checksum)
	}

	return nil
}

// FD returns the host FD of underlying image file.
func (i *Image) FD() int {
	return int(i.src.Fd())
}

// checkRange checks whether the range [off, off+n) is valid.
func (i *Image) checkRange(off, n uint64) bool {
	size := uint64(len(i.bytes))
	end := off + n
	return off < size && off <= end && end <= size
}

// BytesAt returns the bytes at [off, off+n) of the image.
func (i *Image) BytesAt(off, n uint64) ([]byte, error) {
	if ok := i.checkRange(off, n); !ok {
		log.Warningf("Invalid byte range (off: 0x%x, n: 0x%x) for image (size: 0x%x)", off, n, len(i.bytes))
		return nil, linuxerr.EFAULT
	}
	return i.bytes[off : off+n], nil
}

// checkInodeAlignment checks whether off matches inode's alignment requirement.
func checkInodeAlignment(off uint64) bool {
	// Each valid inode should be aligned with an inode slot, which is
	// a fixed value (32 bytes).
	return off&((1<<InodeSlotBits)-1) == 0
}

// inodeFormatAt returns the format of the inode at offset off within the
// memory backed by image.
func (i *Image) inodeFormatAt(off uint64) (uint16, error) {
	if ok := checkInodeAlignment(off); !ok {
		return 0, linuxerr.EFAULT
	}
	if ok := i.checkRange(off, 2); !ok {
		return 0, linuxerr.EFAULT
	}
	return *(*uint16)(i.pointerAt(off)), nil
}

// inodeCompactAt returns a pointer to the compact inode at offset off within
// the memory backed by image.
func (i *Image) inodeCompactAt(off uint64) (*InodeCompact, error) {
	if ok := checkInodeAlignment(off); !ok {
		return nil, linuxerr.EFAULT
	}
	if ok := i.checkRange(off, InodeCompactSize); !ok {
		return nil, linuxerr.EFAULT
	}
	return (*InodeCompact)(i.pointerAt(off)), nil
}

// inodeExtendedAt returns a pointer to the extended inode at offset off within
// the memory backed by image.
func (i *Image) inodeExtendedAt(off uint64) (*InodeExtended, error) {
	if ok := checkInodeAlignment(off); !ok {
		return nil, linuxerr.EFAULT
	}
	if ok := i.checkRange(off, InodeExtendedSize); !ok {
		return nil, linuxerr.EFAULT
	}
	return (*InodeExtended)(i.pointerAt(off)), nil
}

// direntAt returns a pointer to the dirent at offset off within the memory
// backed by image.
func (i *Image) direntAt(off uint64) (*Dirent, error) {
	// Each valid dirent should be aligned to 4 bytes.
	if off&3 != 0 {
		return nil, linuxerr.EFAULT
	}
	if ok := i.checkRange(off, DirentSize); !ok {
		return nil, linuxerr.EFAULT
	}
	return (*Dirent)(i.pointerAt(off)), nil
}

// unmarshalAt deserializes data from the bytes at [off, off+n) of the image.
func (i *Image) unmarshalAt(data marshal.Marshallable, off uint64) error {
	bytes, err := i.BytesAt(off, uint64(data.SizeBytes()))
	if err != nil {
		log.Warningf("Failed to deserialize %T from 0x%x.", data, off)
		return err
	}
	data.UnmarshalUnsafe(bytes)
	return nil
}

// Inode returns the inode identified by nid.
func (i *Image) Inode(nid uint64) (Inode, error) {
	inode := Inode{
		image: i,
		nid:   nid,
	}

	off := i.sb.NidToOffset(nid)
	if format, err := i.inodeFormatAt(off); err != nil {
		return Inode{}, err
	} else {
		inode.format = format
	}

	var (
		rawBlockAddr uint32
		inodeSize    int
	)

	switch layout := inode.Layout(); layout {
	case InodeLayoutCompact:
		ino, err := i.inodeCompactAt(off)
		if err != nil {
			return Inode{}, err
		}

		if ino.XattrCount != 0 {
			log.Warningf("Unsupported xattr at inode (nid=%v)", nid)
			return Inode{}, linuxerr.ENOTSUP
		}

		rawBlockAddr = ino.RawBlockAddr
		inodeSize = ino.SizeBytes()

		inode.size = uint64(ino.Size)
		inode.nlink = uint32(ino.Nlink)
		inode.mode = ino.Mode
		inode.uid = uint32(ino.UID)
		inode.gid = uint32(ino.GID)
		inode.mtime = i.sb.BuildTime
		inode.mtimeNsec = i.sb.BuildTimeNsec

	case InodeLayoutExtended:
		ino, err := i.inodeExtendedAt(off)
		if err != nil {
			return Inode{}, err
		}

		if ino.XattrCount != 0 {
			log.Warningf("Unsupported xattr at inode (nid=%v)", nid)
			return Inode{}, linuxerr.ENOTSUP
		}

		rawBlockAddr = ino.RawBlockAddr
		inodeSize = ino.SizeBytes()

		inode.size = ino.Size
		inode.nlink = ino.Nlink
		inode.mode = ino.Mode
		inode.uid = ino.UID
		inode.gid = ino.GID
		inode.mtime = ino.Mtime
		inode.mtimeNsec = ino.MtimeNsec

	default:
		log.Warningf("Unsupported layout 0x%x at inode (nid=%v)", layout, nid)
		return Inode{}, linuxerr.ENOTSUP
	}

	blockSize := uint64(i.BlockSize())
	inode.blocks = (inode.size + (blockSize - 1)) / blockSize

	switch dataLayout := inode.DataLayout(); dataLayout {
	case InodeDataLayoutFlatInline:
		// Check that whether the file data in the last block fits into
		// the remaining room of the metadata block.
		tailSize := inode.size & (blockSize - 1)
		if tailSize == 0 || tailSize > blockSize-uint64(inodeSize) {
			log.Warningf("Inline data not found or cross block boundary at inode (nid=%v)", nid)
			return Inode{}, linuxerr.EUCLEAN
		}
		inode.idataOff = off + uint64(inodeSize)
		fallthrough

	case InodeDataLayoutFlatPlain:
		inode.dataOff = i.sb.BlockAddrToOffset(rawBlockAddr)

	default:
		log.Warningf("Unsupported data layout 0x%x at inode (nid=%v)", dataLayout, nid)
		return Inode{}, linuxerr.ENOTSUP
	}

	return inode, nil
}

// Inode represents in-memory inode object.
//
// +stateify savable
type Inode struct {
	// image is the underlying image. Inode should not perform writable
	// operations (e.g. Close()) on the image.
	image *Image

	// dataOff points to the data of this inode in the data blocks.
	dataOff uint64

	// idataOff points to the tail packing inline data of this inode
	// if it's not zero in the metadata block.
	idataOff uint64

	// blocks indicates the count of blocks that store the data associated
	// with this inode. It will count in the metadata block that includes
	// the inline data as well.
	blocks uint64

	// format is the format of this inode.
	format uint16

	// Metadata.
	mode      uint16
	nid       uint64
	size      uint64
	mtime     uint64
	mtimeNsec uint32
	uid       uint32
	gid       uint32
	nlink     uint32
}

// bitRange returns the bits within the range [bit, bit+bits) in value.
func bitRange(value, bit, bits uint16) uint16 {
	return (value >> bit) & ((1 << bits) - 1)
}

// Layout returns the inode layout.
func (i *Inode) Layout() uint16 {
	return bitRange(i.format, InodeLayoutBit, InodeLayoutBits)
}

// DataLayout returns the inode data layout.
func (i *Inode) DataLayout() uint16 {
	return bitRange(i.format, InodeDataLayoutBit, InodeDataLayoutBits)
}

// IsRegular indicates whether i represents a regular file.
func (i *Inode) IsRegular() bool {
	return i.mode&linux.S_IFMT == linux.S_IFREG
}

// IsDir indicates whether i represents a directory.
func (i *Inode) IsDir() bool {
	return i.mode&linux.S_IFMT == linux.S_IFDIR
}

// IsCharDev indicates whether i represents a character device.
func (i *Inode) IsCharDev() bool {
	return i.mode&linux.S_IFMT == linux.S_IFCHR
}

// IsBlockDev indicates whether i represents a block device.
func (i *Inode) IsBlockDev() bool {
	return i.mode&linux.S_IFMT == linux.S_IFBLK
}

// IsFIFO indicates whether i represents a named pipe.
func (i *Inode) IsFIFO() bool {
	return i.mode&linux.S_IFMT == linux.S_IFIFO
}

// IsSocket indicates whether i represents a socket.
func (i *Inode) IsSocket() bool {
	return i.mode&linux.S_IFMT == linux.S_IFSOCK
}

// IsSymlink indicates whether i represents a symbolic link.
func (i *Inode) IsSymlink() bool {
	return i.mode&linux.S_IFMT == linux.S_IFLNK
}

// Nid returns the inode number.
func (i *Inode) Nid() uint64 {
	return i.nid
}

// Size returns the data size.
func (i *Inode) Size() uint64 {
	return i.size
}

// Nlink returns the number of hard links.
func (i *Inode) Nlink() uint32 {
	return i.nlink
}

// Mtime returns the time of last modification.
func (i *Inode) Mtime() uint64 {
	return i.mtime
}

// MtimeNsec returns the nano second part of Mtime.
func (i *Inode) MtimeNsec() uint32 {
	return i.mtimeNsec
}

// Mode returns the file type and permissions.
func (i *Inode) Mode() uint16 {
	return i.mode
}

// UID returns the user ID of the owner.
func (i *Inode) UID() uint32 {
	return i.uid
}

// GID returns the group ID of the owner.
func (i *Inode) GID() uint32 {
	return i.gid
}

// DataOffset returns the data offset of this inode in image file.
func (i *Inode) DataOffset() (uint64, error) {
	// TODO: We don't support regular files with inline data yet, which means the image
	// should be created with the "-E noinline_data" option. The "-E noinline_data" option
	// was introduced for the DAX feature support in Linux [1].
	// [1] https://github.com/erofs/erofs-utils/commit/60549d52c3b636f0ddd1d51b0c1517c1dee22595
	if dataLayout := i.DataLayout(); dataLayout != InodeDataLayoutFlatPlain {
		log.Warningf("Unsupported data layout 0x%x at inode (nid=%v)", dataLayout, i.Nid())
		return 0, linuxerr.ENOTSUP
	}
	return i.dataOff, nil
}

// Data returns the read-only file data of this inode.
func (i *Inode) Data() (safemem.BlockSeq, error) {
	switch dataLayout := i.DataLayout(); dataLayout {
	case InodeDataLayoutFlatPlain:
		bytes, err := i.image.BytesAt(i.dataOff, i.size)
		if err != nil {
			return safemem.BlockSeq{}, err
		}
		return safemem.BlockSeqOf(safemem.BlockFromSafeSlice(bytes)), nil

	case InodeDataLayoutFlatInline:
		sl := make([]safemem.Block, 0, 2)
		idataSize := i.size & (uint64(i.image.BlockSize()) - 1)
		if i.size > idataSize {
			if bytes, err := i.image.BytesAt(i.dataOff, i.size-idataSize); err != nil {
				return safemem.BlockSeq{}, err
			} else {
				sl = append(sl, safemem.BlockFromSafeSlice(bytes))
			}
		}
		if bytes, err := i.image.BytesAt(i.idataOff, idataSize); err != nil {
			return safemem.BlockSeq{}, err
		} else {
			sl = append(sl, safemem.BlockFromSafeSlice(bytes))
		}
		return safemem.BlockSeqFromSlice(sl), nil

	default:
		log.Warningf("Unsupported data layout 0x%x at inode (nid=%v)", dataLayout, i.Nid())
		return safemem.BlockSeq{}, linuxerr.ENOTSUP
	}
}

// blockData represents the information of the data in a block.
type blockData struct {
	// base indicates the data offset within the image.
	base uint64
	// size indicates the data size.
	size uint32
}

// valid indicates whether this is valid information about the data in a block.
func (b *blockData) valid() bool {
	// The data offset within the image will never be zero.
	return b.base > 0
}

// getBlockDataInfo returns the information of the data in the block identified by
// blockIdx of this inode.
//
// Precondition: blockIdx < i.blocks.
func (i *Inode) getBlockDataInfo(blockIdx uint64) blockData {
	blockSize := i.image.BlockSize()
	lastBlock := blockIdx == i.blocks-1
	base := i.idataOff
	if !lastBlock || base == 0 {
		base = i.dataOff + blockIdx*uint64(blockSize)
	}
	size := blockSize
	if lastBlock {
		if tailSize := uint32(i.size) & (blockSize - 1); tailSize != 0 {
			size = tailSize
		}
	}
	return blockData{base, size}
}

// getDirentName returns the name of dirent d in the given block of this inode.
//
// The on-disk format of one block looks like this:
//
//	                 ___________________________
//	                /                           |
//	               /              ______________|________________
//	              /              /              | nameoff1       | nameoffN-1
//	 ____________.______________._______________v________________v__________
//	| dirent | dirent | ... | dirent | filename | filename | ... | filename |
//	|___.0___|____1___|_____|___N-1__|____0_____|____1_____|_____|___N-1____|
//	     \                           ^
//	      \                          |                           * could have
//	       \                         |                             trailing '\0'
//	        \________________________| nameoff0
//	                            Directory block
//
// The on-disk format of one directory looks like this:
//
// [ (block 1) dirent 1 | dirent 2 | dirent 3 | name 1 | name 2 | name 3 | optional padding ]
// [ (block 2) dirent 4 | dirent 5 | name 4 | name 5 | optional padding ]
// ...
// [ (block N) dirent M | dirent M+1 | name M | name M+1 | optional padding ]
//
// [ (metadata block) inode | optional fields | dirent M+2 | dirent M+3 | name M+2 | name M+3 | optional padding ]
//
// Refer: https://docs.kernel.org/filesystems/erofs.html#directories
func (i *Inode) getDirentName(d *Dirent, block blockData, lastDirent bool) ([]byte, error) {
	var nameLen uint32
	if lastDirent {
		nameLen = block.size - uint32(d.NameOff)
	} else {
		nameLen = uint32(direntAfter(d).NameOff - d.NameOff)
	}
	if uint32(d.NameOff)+nameLen > block.size || nameLen > MaxNameLen || nameLen == 0 {
		log.Warningf("Corrupted dirent at inode (nid=%v)", i.Nid())
		return nil, linuxerr.EUCLEAN
	}
	name, err := i.image.BytesAt(block.base+uint64(d.NameOff), uint64(nameLen))
	if err != nil {
		return nil, err
	}
	if lastDirent {
		// Optional padding may exist at the end of a block.
		n := bytes.IndexByte(name, 0)
		if n == 0 {
			log.Warningf("Corrupted dirent at inode (nid=%v)", i.Nid())
			return nil, linuxerr.EUCLEAN
		}
		if n != -1 {
			name = name[:n]
		}
	}
	return name, nil
}

// getDirent0 returns a pointer to the first dirent in the given block of this inode.
func (i *Inode) getDirent0(block blockData) (*Dirent, error) {
	d0, err := i.image.direntAt(block.base)
	if err != nil {
		return nil, err
	}
	if d0.NameOff < DirentSize || uint32(d0.NameOff) >= block.size {
		log.Warningf("Invalid nameOff0 %v at inode (nid=%v)", d0.NameOff, i.Nid())
		return nil, linuxerr.EUCLEAN
	}
	return d0, nil
}

// Lookup looks up a child by the name. The child inode number will be returned on success.
func (i *Inode) Lookup(name string) (uint64, error) {
	if !i.IsDir() {
		return 0, linuxerr.ENOTDIR
	}

	// Currently (Go 1.21), there is no safe and efficient way to do three-way
	// string comparisons, so let's convert the string to a byte slice first.
	nameBytes := gohacks.ImmutableBytesFromString(name)

	// In EROFS, all directory entries are _strictly_ recorded in alphabetical
	// order. The lookup is done by directly performing binary search on the
	// disk data similar to what Linux does in fs/erofs/namei.c:erofs_namei().
	var (
		targetBlock      blockData
		targetNumDirents uint16
	)

	// Find the block that may contain the target dirent first.
	bLeft, bRight := int64(0), int64(i.blocks)-1
	for bLeft <= bRight {
		// Cast to uint64 to avoid overflow.
		mid := uint64(bLeft+bRight) >> 1
		block := i.getBlockDataInfo(mid)
		d0, err := i.getDirent0(block)
		if err != nil {
			return 0, err
		}
		numDirents := d0.NameOff / DirentSize
		d0Name, err := i.getDirentName(d0, block, numDirents == 1)
		if err != nil {
			return 0, err
		}
		switch bytes.Compare(nameBytes, d0Name) {
		case 0:
			// Found the target dirent.
			return d0.Nid(), nil
		case 1:
			// name > d0Name, this block may contain the target dirent.
			targetBlock = block
			targetNumDirents = numDirents
			bLeft = int64(mid) + 1
		case -1:
			// name < d0Name, this is not the block we're looking for.
			bRight = int64(mid) - 1
		}
	}

	if !targetBlock.valid() {
		// The target block was not found.
		return 0, linuxerr.ENOENT
	}

	// Find the target dirent in the target block. Note that, as the 0th dirent
	// has already been checked during the block binary search, we don't need to
	// check it again and can define dLeft/dRight as unsigned types.
	dLeft, dRight := uint16(1), targetNumDirents-1
	for dLeft <= dRight {
		// The sum will never lead to a uint16 overflow, as the maximum value of
		// the operands is MaxUint16/DirentSize.
		mid := (dLeft + dRight) >> 1
		direntOff := targetBlock.base + uint64(mid)*DirentSize
		d, err := i.image.direntAt(direntOff)
		if err != nil {
			return 0, err
		}
		dName, err := i.getDirentName(d, targetBlock, mid == targetNumDirents-1)
		if err != nil {
			return 0, err
		}
		switch bytes.Compare(nameBytes, dName) {
		case 0:
			// Found the target dirent.
			return d.Nid(), nil
		case 1:
			// name > dName.
			dLeft = mid + 1
		case -1:
			// name < dName.
			dRight = mid - 1
		}
	}

	return 0, linuxerr.ENOENT
}

// IterDirents invokes cb on each entry in the directory represented by this inode.
// The directory entries will be iterated in alphabetical order.
func (i *Inode) IterDirents(cb func(name string, typ uint8, nid uint64) error) error {
	if !i.IsDir() {
		return linuxerr.ENOTDIR
	}

	// Iterate all the blocks which contain dirents.
	for blockIdx := uint64(0); blockIdx < i.blocks; blockIdx++ {
		block := i.getBlockDataInfo(blockIdx)
		d, err := i.getDirent0(block)
		if err != nil {
			return err
		}
		// Iterate all the dirents in this block.
		numDirents := d.NameOff / DirentSize
		for {
			name, err := i.getDirentName(d, block, numDirents == 1)
			if err != nil {
				return err
			}
			if err := cb(string(name), d.FileType, d.Nid()); err != nil {
				return err
			}
			if numDirents--; numDirents == 0 {
				break
			}
			d = direntAfter(d)
		}
	}
	return nil
}

// Readlink reads the link target.
func (i *Inode) Readlink() (string, error) {
	if !i.IsSymlink() {
		return "", linuxerr.EINVAL
	}
	off := i.dataOff
	size := i.size
	if i.idataOff != 0 {
		// Inline symlink data shouldn't cross block boundary.
		if i.blocks > 1 {
			log.Warningf("Inline data cross block boundary at inode (nid=%v)", i.Nid())
			return "", linuxerr.EUCLEAN
		}
		off = i.idataOff
	} else {
		// This matches Linux's behaviour in fs/namei.c:page_get_link() and
		// include/linux/namei.h:nd_terminate_link().
		if size > hostarch.PageSize-1 {
			size = hostarch.PageSize - 1
		}
	}
	target, err := i.image.BytesAt(off, size)
	if err != nil {
		return "", err
	}
	return string(target), nil
}
