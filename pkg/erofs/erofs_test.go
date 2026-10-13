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

package erofs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
)

func TestOnDiskStructureSizes(t *testing.T) {
	if sb := new(SuperBlock); sb.SizeBytes() != SuperBlockSize {
		t.Errorf("wrong superblock size: want %d, got %d", SuperBlockSize, sb.SizeBytes())
	}

	if i := new(InodeCompact); i.SizeBytes() != InodeCompactSize {
		t.Errorf("wrong compact inode size: want %d, got %d", InodeCompactSize, i.SizeBytes())
	}

	if i := new(InodeExtended); i.SizeBytes() != InodeExtendedSize {
		t.Errorf("wrong extended inode size: want %d, got %d", InodeExtendedSize, i.SizeBytes())
	}

	if d := new(Dirent); d.SizeBytes() != DirentSize {
		t.Errorf("wrong dirent size: want %d, got %d", DirentSize, d.SizeBytes())
	}

	if c := new(ChunkIndex); c.SizeBytes() != ChunkIndexSize {
		t.Errorf("wrong chunk index size: want %d, got %d", ChunkIndexSize, c.SizeBytes())
	}
}

// TestInlineInodeStraddlingBlockBoundary checks that a FlatInline inode whose
// extended inode straddles a block boundary (its inline tail begins in the next
// block) is accepted, not rejected with EUCLEAN. erofs-utils >= 1.9 emits this
// layout and the Linux kernel reads it.
func TestInlineInodeStraddlingBlockBoundary(t *testing.T) {
	const (
		blockSize = 4096
		nid       = 127  // off = nid<<InodeSlotBits = 4064: 32 bytes before block end
		size      = 4050 // tail 4050 > blockSize-InodeExtendedSize (4032), but valid
	)

	img := make([]byte, 3*blockSize)

	sb := SuperBlock{
		Magic:         SuperBlockMagicV1,
		BlockSizeBits: 12, // 4096
		RootNid:       nid,
		Blocks:        3,
	}
	sb.MarshalUnsafe(img[SuperBlockOffset:])

	off := nid << InodeSlotBits
	ino := InodeExtended{
		Format: uint16(InodeLayoutExtended<<InodeLayoutBit | InodeDataLayoutFlatInline<<InodeDataLayoutBit),
		Mode:   0x81a4, // S_IFREG | 0o644
		Size:   size,
		Nlink:  1,
	}
	ino.MarshalUnsafe(img[off:])

	idataOff := off + InodeExtendedSize
	want := make([]byte, size)
	for i := range want {
		want[i] = byte(i % 251)
	}
	copy(img[idataOff:], want)

	f, err := os.CreateTemp(t.TempDir(), "erofs")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.Write(img); err != nil {
		t.Fatalf("Write: %v", err)
	}
	image, err := OpenImage(f) // takes ownership of f
	if err != nil {
		t.Fatalf("OpenImage: %v", err)
	}
	defer image.Close()

	inode, err := image.Inode(nid)
	if err != nil {
		t.Fatalf("Inode(%d): %v", nid, err)
	}
	got, err := image.BytesAt(inode.idataOff, inode.size)
	if err != nil {
		t.Fatalf("BytesAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("inline data mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func chunkImage(t *testing.T, format uint16, extended bool, size uint64, blocks []uint32) *Image {
	t.Helper()
	const page = hostarch.PageSize
	data := make([]byte, 16*page)
	sb := SuperBlock{Magic: SuperBlockMagicV1, BlockSizeBits: hostarch.PageShift, RootNid: 127, Blocks: 16, FeatureIncompat: FeatureIncompatChunkedFile}
	sb.MarshalUnsafe(data[SuperBlockOffset:])
	off := int(sb.RootNid) << InodeSlotBits
	if extended {
		ino := InodeExtended{Format: InodeLayoutExtended | InodeDataLayoutChunkBased<<InodeDataLayoutBit, Mode: 0x81a4, Size: size, Nlink: 1, RawBlockAddr: uint32(format)}
		ino.MarshalUnsafe(data[off:])
		off += InodeExtendedSize
	} else {
		ino := InodeCompact{Format: InodeDataLayoutChunkBased << InodeDataLayoutBit, Mode: 0x81a4, Size: uint32(size), Nlink: 1, RawBlockAddr: uint32(format)}
		ino.MarshalUnsafe(data[off:])
		off += InodeCompactSize
	}
	if format&ChunkFormatIndexes != 0 {
		off = (off + ChunkIndexSize - 1) &^ (ChunkIndexSize - 1)
		for _, block := range blocks {
			idx := ChunkIndex{DeviceID: 0xffff, StartBlkLo: block}
			idx.MarshalUnsafe(data[off:])
			off += ChunkIndexSize
		}
	} else {
		for _, block := range blocks {
			binary.LittleEndian.PutUint32(data[off:], block)
			off += BlockMapEntrySize
		}
	}
	f, err := os.CreateTemp(t.TempDir(), "erofs")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	image, err := OpenImage(f) // takes ownership of f
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(image.Close)
	return image
}

func TestMapChunks(t *testing.T) {
	for _, indexes := range []uint16{0, ChunkFormatIndexes} {
		for _, extended := range []bool{false, true} {
			for _, bits := range []uint16{0, 1, 2} {
				name := fmt.Sprintf("indexes=%t/extended=%t/bits=%d", indexes != 0, extended, bits)
				t.Run(name, func(t *testing.T) {
					const page = hostarch.PageSize
					chunk := uint64(page) << bits
					blocksPerChunk := uint32(1) << bits
					size := 5*chunk + 17
					image := chunkImage(t, indexes|bits, extended, size, []uint32{4, 4 + blocksPerChunk, NullAddr, NullAddr, 12, 4})
					inode, err := image.Inode(image.RootNid())
					if err != nil {
						t.Fatal(err)
					}
					first := Extent{Off: 0, Length: 2 * chunk, ImageOff: 4 * page, Mapped: true}
					second := Extent{Off: chunk, Length: chunk, ImageOff: (4 + uint64(blocksPerChunk)) * page, Mapped: true}
					hole := Extent{Off: 2 * chunk, Length: 2 * chunk}
					lastHole := Extent{Off: 3 * chunk, Length: chunk}
					fifth := Extent{Off: 4 * chunk, Length: chunk, ImageOff: 12 * page, Mapped: true}
					tail := Extent{Off: 5 * chunk, Length: page, ImageOff: 4 * page, Mapped: true}
					for _, tc := range []struct {
						off  uint64
						want Extent
					}{
						{0, first},
						{chunk - 1, first},
						{chunk, second},
						{2*chunk - 1, second},
						{2 * chunk, hole},
						{3*chunk + 13, lastHole},
						{4 * chunk, fifth},
						{5*chunk - 1, fifth},
						{5 * chunk, tail},
						{size - 1, tail},
					} {
						got, err := inode.MapBlocks(tc.off)
						if err != nil {
							t.Fatalf("MapBlocks(%d): %v", tc.off, err)
						}
						if got != tc.want {
							t.Errorf("MapBlocks(%d) = %+v, want %+v", tc.off, got, tc.want)
						}
					}
				})
			}
		}
	}
}

func TestInvalidChunks(t *testing.T) {
	for _, tc := range []struct {
		name     string
		format   uint16
		size     uint64
		blocks   []uint32
		off      uint64
		inodeErr error
		mapErr   error
	}{
		{name: "48-bit addresses", format: 0x40, size: hostarch.PageSize, inodeErr: linuxerr.ENOTSUP},
		{name: "oversized file", size: math.MaxUint64, inodeErr: linuxerr.EUCLEAN},
		{name: "truncated map", size: math.MaxInt64, off: math.MaxInt64 - 1, mapErr: linuxerr.EUCLEAN},
		{name: "past image", size: hostarch.PageSize, blocks: []uint32{16}, mapErr: linuxerr.EUCLEAN},
		{name: "truncated data", format: 1, size: 2 * hostarch.PageSize, blocks: []uint32{15}, mapErr: linuxerr.EUCLEAN},
		{name: "large chunk", format: 31, size: hostarch.PageSize, blocks: []uint32{4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image := chunkImage(t, tc.format, true, tc.size, tc.blocks)
			inode, err := image.Inode(image.RootNid())
			if err != tc.inodeErr {
				t.Fatalf("Inode: %v, want %v", err, tc.inodeErr)
			}
			if err != nil {
				return
			}
			if _, err := inode.MapBlocks(tc.off); err != tc.mapErr {
				t.Errorf("MapBlocks(%d): %v, want %v", tc.off, err, tc.mapErr)
			}
		})
	}
}
