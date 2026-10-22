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
	"fmt"
	"os"
	"slices"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
)

const (
	inlineNid      = 0
	chunkNid       = 32
	chunkDataBlock = 2
	sharedUserID   = 0
)

var (
	inlineInodeOff = int(hostarch.PageSize)
	chunkInodeOff  = int(hostarch.PageSize) + chunkNid<<InodeSlotBits
	inlineIbodyOff = inlineInodeOff + InodeCompactSize
	chunkIbodyOff  = chunkInodeOff + InodeExtendedSize
	sharedXattrOff = 3 * int(hostarch.PageSize)
)

var inlineData = bytes.Repeat([]byte("inline"), 20)

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

// setInlineXattrCount sets the xattr count of the inline inode in data.
func setInlineXattrCount(data []byte, count uint16) {
	var ino InodeCompact
	ino.UnmarshalUnsafe(data[inlineInodeOff:])
	ino.XattrCount = count
	ino.MarshalUnsafe(data[inlineInodeOff:])
}

// xattrImage builds an image with xattrs on two inodes, applying mutate first.
func xattrImage(t testing.TB, mutate func([]byte)) *Image {
	t.Helper()
	data := make([]byte, 4*hostarch.PageSize)
	sb := SuperBlock{Magic: SuperBlockMagicV1, BlockSizeBits: uint8(hostarch.PageShift), Blocks: 4, MetaBlockAddr: 1, XattrBlockAddr: 3, FeatureIncompat: FeatureIncompatChunkedFile}
	sb.MarshalUnsafe(data[SuperBlockOffset:])

	putXattrEntry(data, sharedXattrOff+sharedUserID*xattrSharedIDSize, testXattr{index: xattrIndexUser, name: "shared", value: []byte("s")})

	count := putXattrIbody(data, inlineIbodyOff, []uint32{sharedUserID}, []testXattr{
		{index: xattrIndexUser, name: "inline", value: []byte("inline-value")},
		{index: xattrIndexTrusted, name: "t", value: []byte("trusted-value")},
		{index: xattrIndexSecurity, name: "s", value: []byte("security-value")},
		{index: 0, name: "none", value: []byte("v")},
		{index: 5, name: "lustre", value: []byte("v")},
		{index: 0x80 | xattrIndexUser, name: "long", value: []byte("v")},
	})
	ino := InodeCompact{Format: InodeDataLayoutFlatInline << InodeDataLayoutBit, XattrCount: count, Mode: linux.S_IFREG | 0755, Nlink: 1, Size: uint32(len(inlineData))}
	ino.MarshalUnsafe(data[inlineInodeOff:])
	copy(data[inlineIbodyOff+int(xattrIbodySize(count)):], inlineData)

	count = putXattrIbody(data, chunkIbodyOff, []uint32{sharedUserID}, []testXattr{
		{index: xattrIndexUser, name: "chunk", value: []byte("c")},
	})
	ext := InodeExtended{Format: InodeLayoutExtended<<InodeLayoutBit | InodeDataLayoutChunkBased<<InodeDataLayoutBit, XattrCount: count, Mode: linux.S_IFREG | 0644, Nlink: 1, Size: uint64(hostarch.PageSize), RawBlockAddr: ChunkFormatIndexes}
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

func TestXattrs(t *testing.T) {
	image := xattrImage(t, nil)
	for _, tc := range []struct {
		nid    uint64
		values map[string]string
		names  []string
	}{
		{
			nid: inlineNid,
			values: map[string]string{
				"user.inline": "inline-value",
				"trusted.t":   "trusted-value",
				"security.s":  "security-value",
				"user.shared": "s",
			},
			names: []string{"user.inline", "trusted.t", "security.s", "user.shared"},
		},
		{
			nid:    chunkNid,
			values: map[string]string{"user.chunk": "c", "user.shared": "s"},
			names:  []string{"user.chunk", "user.shared"},
		},
	} {
		t.Run(fmt.Sprintf("nid=%d", tc.nid), func(t *testing.T) {
			inode, err := image.Inode(tc.nid)
			if err != nil {
				t.Fatal(err)
			}
			if names, err := inode.ListXattrs(); err != nil || !slices.Equal(names, tc.names) {
				t.Errorf("ListXattrs() = %q, %v, want %q", names, err, tc.names)
			}
			for name, want := range tc.values {
				if got, err := inode.Xattr(name); err != nil || got != want {
					t.Errorf("Xattr(%q) = %q, %v, want %q", name, got, err, want)
				}
			}
		})
	}
}

func TestXattrNames(t *testing.T) {
	image := xattrImage(t, nil)
	inode, err := image.Inode(inlineNid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		err  *errors.Error
	}{
		{name: "user.", err: linuxerr.EINVAL},
		{name: "user.inl", err: linuxerr.ENODATA},
		{name: "user.long", err: linuxerr.ENODATA},
		{name: "trusted.inline", err: linuxerr.ENODATA},
		{name: "system.posix_acl_access", err: linuxerr.ENOTSUP},
		{name: "foo.bar", err: linuxerr.ENOTSUP},
	} {
		if _, err := inode.Xattr(tc.name); !linuxerr.Equals(tc.err, err) {
			t.Errorf("Xattr(%q) error = %v, want %v", tc.name, err, tc.err)
		}
	}
}

func TestSharedOnlyXattrBody(t *testing.T) {
	image := xattrImage(t, func(data []byte) {
		setInlineXattrCount(data, putXattrIbody(data, inlineIbodyOff, []uint32{sharedUserID}, nil))
	})
	inode, err := image.Inode(inlineNid)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"user.shared"}
	if names, err := inode.ListXattrs(); err != nil || !slices.Equal(names, want) {
		t.Errorf("ListXattrs() = %q, %v, want %q", names, err, want)
	}
}

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
	if extent, err := chunk.MapBlocks(0); err != nil || extent.ImageOff != chunkDataBlock*uint64(hostarch.PageSize) {
		t.Errorf("MapBlocks(0) = %v, %v, want image offset %d", extent, err, chunkDataBlock*uint64(hostarch.PageSize))
	}
}

func TestInvalidXattrs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		nid      uint64
		mutate   func([]byte)
		inodeErr *errors.Error
	}{
		{
			// The id past the body is valid; only the SharedCount bound rejects it.
			name: "shared ids past ibody",
			nid:  inlineNid,
			mutate: func(data []byte) {
				setInlineXattrCount(data, putXattrIbody(data, inlineIbodyOff, []uint32{sharedUserID, sharedUserID}, nil)-1)
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
			if !linuxerr.Equals(tc.inodeErr, err) {
				t.Fatalf("Inode(%d) error = %v, want %v", tc.nid, err, tc.inodeErr)
			}
			if err != nil {
				return
			}
			if _, err := inode.HasPosixACL(); !linuxerr.Equals(linuxerr.EUCLEAN, err) {
				t.Errorf("HasPosixACL() error = %v, want EUCLEAN", err)
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

func TestReservedXattrBody(t *testing.T) {
	image := xattrImage(t, func(data []byte) { setInlineXattrCount(data, 1) })
	inode, err := image.Inode(inlineNid)
	if err != nil {
		t.Fatal(err)
	}
	if hasACL, err := inode.HasPosixACL(); hasACL || err != nil {
		t.Errorf("HasPosixACL() = %t, %v, want false, nil", hasACL, err)
	}
	if _, err := inode.ListXattrs(); !linuxerr.Equals(linuxerr.ENOTSUP, err) {
		t.Errorf("ListXattrs() error = %v, want ENOTSUP", err)
	}
}

func TestHasPosixACL(t *testing.T) {
	acl := []byte{2, 0, 0, 0}
	for _, tc := range []struct {
		name   string
		shared []testXattr
		inline []testXattr
		want   bool
	}{
		{
			name:   "none",
			inline: []testXattr{{index: xattrIndexUser, name: "u"}},
		},
		{
			name:   "access",
			inline: []testXattr{{index: xattrIndexPosixACLAccess, value: acl}},
			want:   true,
		},
		{
			name:   "default",
			inline: []testXattr{{index: xattrIndexPosixACLDefault, value: acl}},
			want:   true,
		},
		{
			name:   "after another entry",
			inline: []testXattr{{index: xattrIndexUser, name: "u"}, {index: xattrIndexPosixACLAccess, value: acl}},
			want:   true,
		},
		{
			name:   "shared",
			shared: []testXattr{{index: xattrIndexPosixACLAccess, value: acl}},
			want:   true,
		},
		{
			name:   "named",
			inline: []testXattr{{index: xattrIndexPosixACLAccess, name: "x", value: acl}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image := xattrImage(t, func(data []byte) {
				var ids []uint32
				off := sharedXattrOff
				for _, x := range tc.shared {
					ids = append(ids, uint32((off-sharedXattrOff)/xattrSharedIDSize))
					off += putXattrEntry(data, off, x)
				}
				setInlineXattrCount(data, putXattrIbody(data, inlineIbodyOff, ids, tc.inline))
			})
			inode, err := image.Inode(inlineNid)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := inode.HasPosixACL(); err != nil || got != tc.want {
				t.Errorf("HasPosixACL() = %v, %v, want %v", got, err, tc.want)
			}
		})
	}
}

func BenchmarkInodeXattrs(b *testing.B) {
	for _, bc := range []struct {
		name   string
		shared []uint32
		inline []testXattr
	}{
		{name: "none"},
		{name: "inline", inline: []testXattr{{index: xattrIndexSecurity, name: "capability", value: make([]byte, linux.XATTR_CAPS_SZ_2)}}},
		{name: "shared", shared: []uint32{sharedUserID}},
	} {
		b.Run(bc.name, func(b *testing.B) {
			image := xattrImage(b, func(data []byte) {
				var count uint16
				if bc.shared != nil || bc.inline != nil {
					count = putXattrIbody(data, inlineIbodyOff, bc.shared, bc.inline)
				}
				setInlineXattrCount(data, count)
			})
			b.ReportAllocs()
			for b.Loop() {
				inode, err := image.Inode(inlineNid)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := inode.HasPosixACL(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
