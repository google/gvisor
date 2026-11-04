// Copyright 2026 The gVisor Authors.
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

package erofs

import (
	"bytes"
	"encoding/binary"
	"os"
	"slices"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// Layout of the image built by xattrImage, with one host page per block.
const (
	inlineNid      = 0
	chunkNid       = 32
	inlineInodeOff = hostarch.PageSize
	chunkInodeOff  = hostarch.PageSize + chunkNid<<InodeSlotBits
	inlineIbodyOff = inlineInodeOff + InodeCompactSize
	chunkIbodyOff  = chunkInodeOff + InodeExtendedSize
	chunkDataBlock = 2
	sharedXattrOff = 3 * hostarch.PageSize
	sharedUserID   = 0
)

// inlineData is the inline file data of the compact inode in xattrImage.
var inlineData = bytes.Repeat([]byte("inline"), 20)

// testXattr is an extended attribute entry to write into a test image.
type testXattr struct {
	index uint8
	name  string
	value []byte
}

// putXattrEntry writes an entry at data[off:] and returns its padded size.
func putXattrEntry(data []byte, off int, x testXattr) int {
	header := xattrEntryHeader{NameLen: uint8(len(x.name)), NameIndex: x.index, ValueSize: uint16(len(x.value))}
	header.MarshalUnsafe(data[off:])
	copy(data[off+xattrEntrySize:], x.name)
	copy(data[off+xattrEntrySize+len(x.name):], x.value)
	return (xattrEntrySize + len(x.name) + len(x.value) + xattrEntrySize - 1) &^ (xattrEntrySize - 1)
}

// putXattrIbody writes an xattr body at data[off:] and returns its count.
func putXattrIbody(data []byte, off int, shared []uint32, inline []testXattr) uint16 {
	header := xattrIbodyHeader{SharedCount: uint8(len(shared))}
	header.MarshalUnsafe(data[off:])
	pos := off + xattrIbodyHeaderSize
	for _, id := range shared {
		binary.LittleEndian.PutUint32(data[pos:], id)
		pos += xattrSharedIDSize
	}
	for _, x := range inline {
		pos += putXattrEntry(data, pos, x)
	}
	return uint16((pos-off-xattrIbodyHeaderSize)/xattrEntrySize + 1)
}

// setInlineXattrCount sets the xattr count of the inline inode.
func setInlineXattrCount(data []byte, count uint16) {
	var ino InodeCompact
	ino.UnmarshalUnsafe(data[inlineInodeOff:])
	ino.XattrCount = count
	ino.MarshalUnsafe(data[inlineInodeOff:])
}

// xattrImage returns an image with a compact inline inode and an extended
// chunk-based inode that have xattrs. If mutate is not nil, it changes the
// image data before the image is opened.
func xattrImage(t *testing.T, mutate func([]byte)) *Image {
	t.Helper()
	data := make([]byte, 4*hostarch.PageSize)
	sb := SuperBlock{Magic: SuperBlockMagicV1, BlockSizeBits: uint8(hostarch.PageShift), Blocks: 4, MetaBlockAddr: 1, XattrBlockAddr: 3, FeatureIncompat: FeatureIncompatChunkedFile}
	sb.MarshalUnsafe(data[SuperBlockOffset:])

	putXattrEntry(data, sharedXattrOff+sharedUserID*xattrSharedIDSize, testXattr{index: xattrIndexUser, name: "shared", value: []byte("s")})

	count := putXattrIbody(data, inlineIbodyOff, []uint32{sharedUserID}, []testXattr{
		{index: xattrIndexUser, name: "inline", value: []byte("inline-value")},
		{index: 0x80 | xattrIndexUser, name: "long", value: []byte("v")},
	})
	ino := InodeCompact{Format: InodeDataLayoutFlatInline << InodeDataLayoutBit, XattrCount: count, Mode: linux.S_IFREG | 0755, Nlink: 1, Size: uint32(len(inlineData))}
	ino.MarshalUnsafe(data[inlineInodeOff:])
	copy(data[inlineIbodyOff+int(xattrIbodySize(count)):], inlineData)

	count = putXattrIbody(data, chunkIbodyOff, []uint32{sharedUserID}, []testXattr{
		{index: xattrIndexUser, name: "chunk", value: []byte("c")},
	})
	ext := InodeExtended{Format: InodeLayoutExtended<<InodeLayoutBit | InodeDataLayoutChunkBased<<InodeDataLayoutBit, XattrCount: count, Mode: linux.S_IFREG | 0644, Nlink: 1, Size: hostarch.PageSize, RawBlockAddr: ChunkFormatIndexes}
	ext.MarshalUnsafe(data[chunkInodeOff:])
	// This xattr body requires padding before the 8-byte chunk indexes.
	chunkIndexOff := (chunkIbodyOff + int(xattrIbodySize(count)) + ChunkIndexSize - 1) &^ (ChunkIndexSize - 1)
	index := ChunkIndex{StartBlkLo: chunkDataBlock}
	index.MarshalUnsafe(data[chunkIndexOff:])

	if mutate != nil {
		mutate(data)
	}
	f, err := os.CreateTemp(t.TempDir(), "erofs")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	image, err := OpenImage(f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(image.Close)
	return image
}

// TestUnknownXattrIndex checks that unsupported disk entries are skipped.
func TestUnknownXattrIndex(t *testing.T) {
	image := xattrImage(t, nil)
	inode, err := image.Inode(inlineNid)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"user.inline", "user.shared"}
	if names, err := inode.ListXattrs(); err != nil || !slices.Equal(names, want) {
		t.Errorf("ListXattrs() = %q, %v, want %q", names, err, want)
	}
	if _, err := inode.Xattr("user.long"); !linuxerr.Equals(linuxerr.ENODATA, err) {
		t.Errorf("Xattr(user.long) error = %v, want ENODATA", err)
	}
}

// TestXattrDataOffsets checks data locations after an inode's xattr storage.
func TestXattrDataOffsets(t *testing.T) {
	image := xattrImage(t, nil)
	inline, err := image.Inode(inlineNid)
	if err != nil {
		t.Fatal(err)
	}
	extent, err := inline.MapBlocks(0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := image.BytesAt(extent.ImageOff, uint64(len(inlineData)))
	if err != nil || !bytes.Equal(got, inlineData) {
		t.Errorf("inline data = %q, %v, want %q", got, err, inlineData)
	}
	chunk, err := image.Inode(chunkNid)
	if err != nil {
		t.Fatal(err)
	}
	if extent, err := chunk.MapBlocks(0); err != nil || extent.ImageOff != chunkDataBlock*hostarch.PageSize {
		t.Errorf("MapBlocks(0) = %v, %v, want image offset %d", extent, err, chunkDataBlock*hostarch.PageSize)
	}
}

// TestInvalidXattrs checks truncated and out-of-range xattr metadata.
func TestInvalidXattrs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		nid      uint64
		mutate   func([]byte)
		inodeErr error
	}{
		{
			name: "shared ids past ibody",
			nid:  inlineNid,
			mutate: func(data []byte) {
				header := xattrIbodyHeader{SharedCount: 255}
				header.MarshalUnsafe(data[inlineIbodyOff:])
			},
		},
		{
			name: "inline entry past ibody",
			nid:  inlineNid,
			mutate: func(data []byte) {
				setInlineXattrCount(data, 2)
				var header xattrIbodyHeader
				header.MarshalUnsafe(data[inlineIbodyOff:])
				putXattrEntry(data, inlineIbodyOff+xattrIbodyHeaderSize, testXattr{index: xattrIndexUser, name: "x"})
			},
		},
		{
			name: "shared value past image",
			nid:  inlineNid,
			mutate: func(data []byte) {
				header := xattrEntryHeader{NameLen: uint8(len("shared")), NameIndex: xattrIndexUser, ValueSize: 0xffff}
				header.MarshalUnsafe(data[sharedXattrOff+sharedUserID*xattrSharedIDSize:])
			},
		},
		{
			name: "shared id past image",
			nid:  chunkNid,
			mutate: func(data []byte) {
				binary.LittleEndian.PutUint32(data[chunkIbodyOff+xattrIbodyHeaderSize:], ^uint32(0))
			},
		},
		{
			name:     "ibody past image",
			nid:      inlineNid,
			mutate:   func(data []byte) { setInlineXattrCount(data, 0xffff) },
			inodeErr: linuxerr.EUCLEAN,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image := xattrImage(t, tc.mutate)
			inode, err := image.Inode(tc.nid)
			if err != tc.inodeErr {
				t.Fatalf("Inode(%d) error = %v, want %v", tc.nid, err, tc.inodeErr)
			}
			if err != nil {
				return
			}
			if _, err := inode.ListXattrs(); !linuxerr.Equals(linuxerr.EUCLEAN, err) {
				t.Errorf("ListXattrs() error = %v, want EUCLEAN", err)
			}
			if _, err := inode.Xattr("user.missing"); !linuxerr.Equals(linuxerr.EUCLEAN, err) {
				t.Errorf("Xattr() error = %v, want EUCLEAN", err)
			}
		})
	}
}

// TestReservedXattrBody checks the undefined header-only xattr representation.
func TestReservedXattrBody(t *testing.T) {
	image := xattrImage(t, func(data []byte) { setInlineXattrCount(data, 1) })
	inode, err := image.Inode(inlineNid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inode.ListXattrs(); !linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
		t.Errorf("ListXattrs() error = %v, want EOPNOTSUPP", err)
	}
}

// TestPOSIXACLIndexes checks both on-disk ACL indexes.
func TestPOSIXACLIndexes(t *testing.T) {
	for _, index := range []uint8{xattrIndexPosixACLAccess, xattrIndexPosixACLDefault} {
		image := xattrImage(t, func(data []byte) {
			count := putXattrIbody(data, inlineIbodyOff, nil, []testXattr{
				{index: index, value: []byte{2, 0, 0, 0}},
			})
			setInlineXattrCount(data, count)
		})
		inode, err := image.Inode(inlineNid)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := inode.HasPOSIXACL(); err != nil || !got {
			t.Errorf("index %d: HasPOSIXACL() = %v, %v, want true", index, got, err)
		}
	}
}
