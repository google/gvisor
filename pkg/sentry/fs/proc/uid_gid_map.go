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

package proc

import (
	"bytes"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

// idMapInodeOperations implements fs.InodeOperations for
// /proc/[pid]/{uid,gid}_map.
//
// +stateify savable
type idMapInodeOperations struct {
	fsutil.InodeGenericChecker `state:"nosave"`
	fsutil.InodeNoopRelease    `state:"nosave"`
	fsutil.InodeNoopWriteOut   `state:"nosave"`
	fsutil.InodeNotAllocatable `state:"nosave"`
	fsutil.InodeNotDirectory   `state:"nosave"`
	fsutil.InodeNotMappable    `state:"nosave"`
	fsutil.InodeNotSocket      `state:"nosave"`
	fsutil.InodeNotSymlink     `state:"nosave"`
	fsutil.InodeNotTruncatable `state:"nosave"`
	fsutil.InodeVirtual        `state:"nosave"`

	fsutil.InodeSimpleAttributes
	fsutil.InodeSimpleExtendedAttributes

	t    *kernel.Task
	gids bool
}

var _ fs.InodeOperations = (*idMapInodeOperations)(nil)

// newUIDMap returns a new uid_map file.
func newUIDMap(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	return newIDMap(t, msrc, false /* gids */)
}

// newGIDMap returns a new gid_map file.
func newGIDMap(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	return newIDMap(t, msrc, true /* gids */)
}

func newIDMap(t *kernel.Task, msrc *fs.MountSource, gids bool) *fs.Inode {
	return newProcInode(&idMapInodeOperations{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(t, fs.RootOwner, fs.FilePermsFromMode(0644), linux.PROC_SUPER_MAGIC),
		t:                     t,
		gids:                  gids,
	}, msrc, fs.SpecialFile, t)
}

// GetFile implements fs.InodeOperations.GetFile.
func (imio *idMapInodeOperations) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &idMapFileOperations{
		iops: imio,
	}), nil
}

// +stateify savable
type idMapFileOperations struct {
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`

	iops *idMapInodeOperations
}

var _ fs.FileOperations = (*idMapFileOperations)(nil)

// "There is an (arbitrary) limit on the number of lines in the file. As at
// Linux 3.18, the limit is five lines." - user_namespaces(7)
const maxIDMapLines = 5

// Read implements fs.FileOperations.Read.
func (imfo *idMapFileOperations) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	var entries []auth.IDMapEntry
	if imfo.iops.gids {
		entries = imfo.iops.t.UserNamespace().GIDMap()
	} else {
		entries = imfo.iops.t.UserNamespace().UIDMap()
	}
	var buf bytes.Buffer
	for _, e := range entries {
		fmt.Fprintf(&buf, "%10d %10d %10d\n", e.FirstID, e.FirstParentID, e.Length)
	}
	if offset >= int64(buf.Len()) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, buf.Bytes()[offset:])
	return int64(n), err
}

// Write implements fs.FileOperations.Write.
func (imfo *idMapFileOperations) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	// "In addition, the number of bytes written to the file must be less than
	// the system page size, and the write must be performed at the start of
	// the file ..." - user_namespaces(7)
	srclen := src.NumBytes()
	if srclen >= usermem.PageSize || offset != 0 {
		return 0, syserror.EINVAL
	}
	b := make([]byte, srclen)
	if _, err := src.CopyIn(ctx, b); err != nil {
		return 0, err
	}

	// Truncate from the first NULL byte.
	var nul int64
	nul = int64(bytes.IndexByte(b, 0))
	if nul == -1 {
		nul = srclen
	}
	b = b[:nul]
	// Remove the last \n.
	if nul >= 1 && b[nul-1] == '\n' {
		b = b[:nul-1]
	}
	lines := bytes.SplitN(b, []byte("\n"), maxIDMapLines+1)
	if len(lines) > maxIDMapLines {
		return 0, syserror.EINVAL
	}

	entries := make([]auth.IDMapEntry, len(lines))
	for i, l := range lines {
		var e auth.IDMapEntry
		_, err := fmt.Sscan(string(l), &e.FirstID, &e.FirstParentID, &e.Length)
		if err != nil {
			return 0, syserror.EINVAL
		}
		entries[i] = e
	}
	var err error
	if imfo.iops.gids {
		err = imfo.iops.t.UserNamespace().SetGIDMap(ctx, entries)
	} else {
		err = imfo.iops.t.UserNamespace().SetUIDMap(ctx, entries)
	}
	if err != nil {
		return 0, err
	}

	// On success, Linux's kernel/user_namespace.c:map_write() always returns
	// count, even if fewer bytes were used.
	return int64(srclen), nil
}
