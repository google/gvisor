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
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
)

// Extended attribute name indexes.
const (
	xattrIndexUser            = 1
	xattrIndexPosixACLAccess  = 2
	xattrIndexPosixACLDefault = 3
	xattrIndexTrusted         = 4
	xattrIndexSecurity        = 6
)

// Sizes of on-disk extended attribute structures in bytes.
const (
	xattrIbodyHeaderSize = 12
	xattrEntrySize       = 4
	xattrSharedIDSize    = 4
)

// xattrIbodyHeader is the on-disk header of an inode's extended attributes.
//
// +marshal
type xattrIbodyHeader struct {
	_           uint32
	SharedCount uint8
	_           [7]byte
}

// xattrEntryHeader is the on-disk header of one extended attribute.
//
// +marshal
type xattrEntryHeader struct {
	NameLen   uint8
	NameIndex uint8
	ValueSize uint16
}

// xattrPrefixes maps name indexes to the name prefixes they stand for.
var xattrPrefixes = [...]string{
	xattrIndexUser:     linux.XATTR_USER_PREFIX,
	xattrIndexTrusted:  linux.XATTR_TRUSTED_PREFIX,
	xattrIndexSecurity: linux.XATTR_SECURITY_PREFIX,
}

// xattrPrefix returns the name prefix for a name index, or "" if the index is
// not supported.
func xattrPrefix(index uint8) string {
	if int(index) >= len(xattrPrefixes) {
		return ""
	}
	return xattrPrefixes[index]
}

// xattrIbodySize returns the size of the extended attribute area that
// follows an on-disk inode with the given xattr count.
func xattrIbodySize(xattrCount uint16) uint64 {
	if xattrCount == 0 {
		return 0
	}
	return xattrIbodyHeaderSize + uint64(xattrCount-1)*xattrEntrySize
}

// xattrIbodyOff returns the image offset of the inode's extended attribute
// area, which follows the on-disk inode.
func (i *Inode) xattrIbodyOff() uint64 {
	if i.Layout() == InodeLayoutExtended {
		return i.image.sb.NidToOffset(i.nid) + InodeExtendedSize
	}
	return i.image.sb.NidToOffset(i.nid) + InodeCompactSize
}

// xattrEntry is an extended attribute entry within the image.
type xattrEntry struct {
	index uint8
	name  []byte
	value []byte
}

// xattrEntryAt returns the extended attribute entry at offset off within the
// image, and the size of the entry including its padding.
// Each entry is padded to a 4-byte boundary.
func (i *Image) xattrEntryAt(off uint64) (xattrEntry, uint64, error) {
	if !i.checkRange(off, xattrEntrySize) {
		return xattrEntry{}, 0, linuxerr.EUCLEAN
	}
	header := (*xattrEntryHeader)(i.pointerAt(off))
	nameLen := uint64(header.NameLen)
	valueSize := uint64(header.ValueSize)
	size := xattrEntrySize + nameLen + valueSize
	if !i.checkRange(off, size) {
		return xattrEntry{}, 0, linuxerr.EUCLEAN
	}
	nameOff := off + xattrEntrySize
	valueOff := nameOff + nameLen
	return xattrEntry{
		index: header.NameIndex,
		name:  i.bytes[nameOff:valueOff],
		value: i.bytes[valueOff : valueOff+valueSize],
	}, (size + xattrEntrySize - 1) &^ (xattrEntrySize - 1), nil
}

// forEachXattr calls fn for each extended attribute entry of the inode until
// fn returns false. Inline entries are visited before shared entries, as in
// fs/erofs/xattr.c:erofs_xattr_iter_inline() and erofs_xattr_iter_shared().
func (i *Inode) forEachXattr(fn func(xattrEntry) bool) error {
	corruptionErr := func() error {
		log.Warningf("Corrupted xattrs at inode (nid=%v)", i.Nid())
		return linuxerr.EUCLEAN
	}
	ibodySize := xattrIbodySize(i.xattrCount)
	if ibodySize == 0 {
		return nil
	}
	if ibodySize == xattrIbodyHeaderSize {
		log.Warningf("Xattr header without entries at inode (nid=%v)", i.Nid())
		return linuxerr.EOPNOTSUPP
	}
	ibodyOff := i.xattrIbodyOff()
	header := (*xattrIbodyHeader)(i.image.pointerAt(ibodyOff))
	sharedCount := uint64(header.SharedCount)
	pos := xattrIbodyHeaderSize + sharedCount*xattrSharedIDSize
	if pos > ibodySize {
		return corruptionErr()
	}
	for pos < ibodySize {
		entry, size, err := i.image.xattrEntryAt(ibodyOff + pos)
		if err != nil || size > ibodySize-pos {
			return corruptionErr()
		}
		if !fn(entry) {
			return nil
		}
		pos += size
	}
	sharedBase := i.image.sb.BlockAddrToOffset(i.image.sb.XattrBlockAddr)
	for j := uint64(0); j < sharedCount; j++ {
		id := *(*uint32)(i.image.pointerAt(ibodyOff + xattrIbodyHeaderSize + j*xattrSharedIDSize))
		entry, _, err := i.image.xattrEntryAt(sharedBase + uint64(id)*xattrSharedIDSize)
		if err != nil {
			return corruptionErr()
		}
		if !fn(entry) {
			return nil
		}
	}
	return nil
}

// HasPOSIXACL reports whether the inode has a POSIX access or default ACL.
func (i *Inode) HasPOSIXACL() (bool, error) {
	var found bool
	err := i.forEachXattr(func(entry xattrEntry) bool {
		found = (entry.index == xattrIndexPosixACLAccess || entry.index == xattrIndexPosixACLDefault) && len(entry.name) == 0
		return !found
	})
	return found, err
}

// ListXattrs returns the names of the inode's extended attributes. Entries
// with a name index that this implementation does not support are skipped,
// as in fs/erofs/xattr.c:erofs_listxattr().
func (i *Inode) ListXattrs() ([]string, error) {
	var names []string
	if err := i.forEachXattr(func(entry xattrEntry) bool {
		if prefix := xattrPrefix(entry.index); prefix != "" {
			names = append(names, prefix+string(entry.name))
		}
		return true
	}); err != nil {
		return nil, err
	}
	return names, nil
}

// Xattr returns the value of the extended attribute with the given name.
//
// The returned slice aliases the image and must not be modified.
func (i *Inode) Xattr(name string) ([]byte, error) {
	var index uint8
	for j, prefix := range xattrPrefixes {
		if prefix != "" && strings.HasPrefix(name, prefix) {
			index = uint8(j)
			break
		}
	}
	if index == 0 {
		return nil, linuxerr.EOPNOTSUPP
	}
	suffix := name[len(xattrPrefixes[index]):]
	if suffix == "" {
		return nil, linuxerr.EINVAL
	}
	var (
		value []byte
		found bool
	)
	if err := i.forEachXattr(func(entry xattrEntry) bool {
		if entry.index == index && string(entry.name) == suffix {
			value, found = entry.value, true
		}
		return !found
	}); err != nil {
		return nil, err
	}
	if !found {
		return nil, linuxerr.ENODATA
	}
	return value, nil
}
