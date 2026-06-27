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
	"os"
	"testing"
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
