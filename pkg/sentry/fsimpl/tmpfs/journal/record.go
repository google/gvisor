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

package journal

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// RecordType identifies the payload format of a journal record.
type RecordType uint16

// Record types.
const (
	// RecordRoot names the root inode and the next free inode number. It is
	// the first record of every snapshot.
	RecordRoot RecordType = iota + 1

	// RecordInode holds the full state of one inode.
	RecordInode

	// RecordInodeFree deletes an inode that has no links.
	RecordInodeFree

	// RecordDirentAdd adds a directory entry.
	RecordDirentAdd

	// RecordDirentDel removes a directory entry.
	RecordDirentDel

	// RecordRename moves or exchanges directory entries in one record, so
	// that a crash cannot apply only part of a rename.
	RecordRename

	// RecordExtentSet maps a page-aligned range of a regular file to a range
	// of the filestore.
	RecordExtentSet

	// RecordExtentClear unmaps a page-aligned range of a regular file.
	RecordExtentClear

	numRecordTypes
)

// String implements fmt.Stringer.
func (t RecordType) String() string {
	switch t {
	case RecordRoot:
		return "ROOT"
	case RecordInode:
		return "INODE"
	case RecordInodeFree:
		return "INODE_FREE"
	case RecordDirentAdd:
		return "DIRENT_ADD"
	case RecordDirentDel:
		return "DIRENT_DEL"
	case RecordRename:
		return "RENAME"
	case RecordExtentSet:
		return "EXTENT_SET"
	case RecordExtentClear:
		return "EXTENT_CLEAR"
	default:
		return fmt.Sprintf("RecordType(%d)", uint16(t))
	}
}

// Record layout within a region. All integers are little-endian.
//
//	0:  magic   u32 (written last, with an atomic store)
//	4:  len     u32 (payload length)
//	8:  seq     u64
//	16: type    u16
//	18: flags   u16 (must be 0)
//	20: unused  u32 (must be 0)
//	24: payload [len]byte
//	24+len: crc32c u32 over bytes [4, 24+len)
//
// The total record size is rounded up to a multiple of 8 bytes.
const (
	recordMagic      = 0x4c4e524a // "JRNL"
	recordHeaderSize = 24
	recordCRCSize    = 4
)

// recordSize returns the size that a record with the given payload length
// takes in a region.
func recordSize(payloadLen uint64) uint64 {
	return (recordHeaderSize + payloadLen + recordCRCSize + 7) &^ 7
}

// Bounds on untrusted input.
const (
	// MaxNameLen is the maximum length of a directory entry name.
	MaxNameLen = 255

	// MaxSymlinkLen is the maximum length of a symlink target.
	MaxSymlinkLen = 4096

	// MaxXattrNameLen is the maximum length of an extended attribute name.
	MaxXattrNameLen = 255

	// MaxXattrValueLen is the maximum length of an extended attribute value.
	MaxXattrValueLen = 65536

	// MaxXattrs is the maximum number of extended attributes on an inode.
	MaxXattrs = 1024

	// MaxInodes is the maximum number of inodes in a replayed state.
	MaxInodes = 1 << 24
)

func castagnoli() *crc32.Table {
	// crc32.MakeTable returns a cached table for crc32.Castagnoli.
	return crc32.MakeTable(crc32.Castagnoli)
}

// Xattr is one extended attribute.
type Xattr struct {
	Name  string
	Value string
}

// InodeRecord is the payload of a RecordInode record.
type InodeRecord struct {
	Ino   uint64
	Mode  uint32
	UID   uint32
	GID   uint32
	Atime int64
	Mtime int64
	Ctime int64
	Btime int64
	// Size is the size of a regular file. It is 0 for other file types.
	Size      uint64
	RdevMajor uint32
	RdevMinor uint32
	// Target is the target of a symlink. It is empty for other file types.
	Target string
	// Xattrs holds the extended attributes of the inode, including POSIX
	// ACLs in their xattr representation.
	Xattrs []Xattr
}

const inodeFixedLen = 8 + 4*3 + 8*4 + 8 + 4*2 + 4 /* target len */ + 4 /* nxattrs */

func (r *InodeRecord) payloadLen() uint64 {
	n := uint64(inodeFixedLen) + uint64(len(r.Target))
	for i := range r.Xattrs {
		n += 2 + uint64(len(r.Xattrs[i].Name)) + 4 + uint64(len(r.Xattrs[i].Value))
	}
	return n
}

func (r *InodeRecord) encode(e *encoder) {
	e.u64(r.Ino)
	e.u32(r.Mode)
	e.u32(r.UID)
	e.u32(r.GID)
	e.u64(uint64(r.Atime))
	e.u64(uint64(r.Mtime))
	e.u64(uint64(r.Ctime))
	e.u64(uint64(r.Btime))
	e.u64(r.Size)
	e.u32(r.RdevMajor)
	e.u32(r.RdevMinor)
	e.str32(r.Target)
	e.u32(uint32(len(r.Xattrs)))
	for i := range r.Xattrs {
		e.str16(r.Xattrs[i].Name)
		e.str32(r.Xattrs[i].Value)
	}
}

func (r *InodeRecord) decode(d *decoder) error {
	r.Ino = d.u64()
	r.Mode = d.u32()
	r.UID = d.u32()
	r.GID = d.u32()
	r.Atime = int64(d.u64())
	r.Mtime = int64(d.u64())
	r.Ctime = int64(d.u64())
	r.Btime = int64(d.u64())
	r.Size = d.u64()
	r.RdevMajor = d.u32()
	r.RdevMinor = d.u32()
	r.Target = d.str32(MaxSymlinkLen)
	n := d.u32()
	if d.err != nil {
		return d.err
	}
	if n > MaxXattrs {
		return fmt.Errorf("inode %d has %d xattrs, more than %d", r.Ino, n, MaxXattrs)
	}
	r.Xattrs = nil
	if n != 0 {
		r.Xattrs = make([]Xattr, n)
	}
	for i := range r.Xattrs {
		r.Xattrs[i].Name = d.str16(MaxXattrNameLen)
		r.Xattrs[i].Value = d.str32(MaxXattrValueLen)
	}
	return d.err
}

// encoder writes little-endian values into a byte slice. Callers must size
// buf in advance.
type encoder struct {
	buf []byte
	off int
}

func (e *encoder) u16(v uint16) {
	binary.LittleEndian.PutUint16(e.buf[e.off:], v)
	e.off += 2
}

func (e *encoder) u32(v uint32) {
	binary.LittleEndian.PutUint32(e.buf[e.off:], v)
	e.off += 4
}

func (e *encoder) u64(v uint64) {
	binary.LittleEndian.PutUint64(e.buf[e.off:], v)
	e.off += 8
}

func (e *encoder) str16(s string) {
	e.u16(uint16(len(s)))
	e.off += copy(e.buf[e.off:], s)
}

func (e *encoder) str32(s string) {
	e.u32(uint32(len(s)))
	e.off += copy(e.buf[e.off:], s)
}

// decoder reads little-endian values from an untrusted byte slice. The first
// out-of-bounds read sets err; later reads return zero values.
type decoder struct {
	buf []byte
	off int
	err error
}

func (d *decoder) need(n int) bool {
	if d.err != nil {
		return false
	}
	if n < 0 || len(d.buf)-d.off < n {
		d.err = fmt.Errorf("truncated payload: need %d bytes at offset %d of %d", n, d.off, len(d.buf))
		return false
	}
	return true
}

func (d *decoder) u16() uint16 {
	if !d.need(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(d.buf[d.off:])
	d.off += 2
	return v
}

func (d *decoder) u32() uint32 {
	if !d.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(d.buf[d.off:])
	d.off += 4
	return v
}

func (d *decoder) u64() uint64 {
	if !d.need(8) {
		return 0
	}
	v := binary.LittleEndian.Uint64(d.buf[d.off:])
	d.off += 8
	return v
}

func (d *decoder) bytes(n int, max int) string {
	if d.err == nil && n > max {
		d.err = fmt.Errorf("string length %d exceeds limit %d", n, max)
	}
	if !d.need(n) {
		return ""
	}
	s := string(d.buf[d.off : d.off+n])
	d.off += n
	return s
}

func (d *decoder) str16(max int) string {
	return d.bytes(int(d.u16()), max)
}

func (d *decoder) str32(max int) string {
	return d.bytes(int(d.u32()), max)
}

// done returns an error if d failed or if bytes remain unread.
func (d *decoder) done() error {
	if d.err != nil {
		return d.err
	}
	if d.off != len(d.buf) {
		return fmt.Errorf("%d trailing payload bytes", len(d.buf)-d.off)
	}
	return nil
}
