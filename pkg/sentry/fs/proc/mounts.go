// Copyright 2018 Google LLC
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
	"sort"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
)

// forEachMountSource runs f for the process root mount and  each mount that is a
// descendant of the root.
func forEachMountSource(t *kernel.Task, fn func(string, *fs.MountSource)) {
	var fsctx *kernel.FSContext
	t.WithMuLocked(func(t *kernel.Task) {
		fsctx = t.FSContext()
	})
	if fsctx == nil {
		// The task has been destroyed. Nothing to show here.
		return
	}

	// All mount points must be relative to the rootDir, and mounts outside
	// will be excluded.
	rootDir := fsctx.RootDirectory()
	if rootDir == nil {
		// The task has been destroyed. Nothing to show here.
		return
	}
	defer rootDir.DecRef()

	if rootDir.Inode == nil {
		panic(fmt.Sprintf("root dirent has nil inode: %+v", rootDir))
	}
	if rootDir.Inode.MountSource == nil {
		panic(fmt.Sprintf("root dirent has nil mount: %+v", rootDir))
	}

	ms := append(rootDir.Inode.MountSource.Submounts(), rootDir.Inode.MountSource)
	sort.Slice(ms, func(i, j int) bool {
		return ms[i].ID() < ms[j].ID()
	})
	for _, m := range ms {
		mroot := m.Root()
		mountPath, desc := mroot.FullName(rootDir)
		mroot.DecRef()
		if !desc {
			// MountSources that are not descendants of the chroot jail are ignored.
			continue
		}

		fn(mountPath, m)
	}
}

// mountInfoFile is used to implement /proc/[pid]/mountinfo.
//
// +stateify savable
type mountInfoFile struct {
	t *kernel.Task
}

// NeedsUpdate implements SeqSource.NeedsUpdate.
func (mif *mountInfoFile) NeedsUpdate(_ int64) bool {
	return true
}

// ReadSeqFileData implements SeqSource.ReadSeqFileData.
func (mif *mountInfoFile) ReadSeqFileData(ctx context.Context, handle seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if handle != nil {
		return nil, 0
	}

	var buf bytes.Buffer
	forEachMountSource(mif.t, func(mountPath string, m *fs.MountSource) {
		// Format:
		// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
		// (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)

		// (1) MountSource ID.
		fmt.Fprintf(&buf, "%d ", m.ID())

		// (2)  Parent ID (or this ID if there is no parent).
		pID := m.ID()
		if p := m.Parent(); p != nil {
			pID = p.ID()
		}
		fmt.Fprintf(&buf, "%d ", pID)

		// (3) Major:Minor device ID. We don't have a superblock, so we
		// just use the root inode device number.
		mroot := m.Root()
		sa := mroot.Inode.StableAttr
		mroot.DecRef()
		fmt.Fprintf(&buf, "%d:%d ", sa.DeviceFileMajor, sa.DeviceFileMinor)

		// (4) Root: the pathname of the directory in the filesystem
		// which forms the root of this mount.
		//
		// NOTE: This will always be "/" until we implement
		// bind mounts.
		fmt.Fprintf(&buf, "/ ")

		// (5) Mount point (relative to process root).
		fmt.Fprintf(&buf, "%s ", mountPath)

		// (6) Mount options.
		opts := "rw"
		if m.Flags.ReadOnly {
			opts = "ro"
		}
		if m.Flags.NoAtime {
			opts += ",noatime"
		}
		fmt.Fprintf(&buf, "%s ", opts)

		// (7) Optional fields: zero or more fields of the form "tag[:value]".
		// (8) Separator: the end of the optional fields is marked by a single hyphen.
		fmt.Fprintf(&buf, "- ")

		// (9) Filesystem type.
		name := "none"
		if m.Filesystem != nil {
			name = m.Filesystem.Name()
		}
		fmt.Fprintf(&buf, "%s ", name)

		// (10) Mount source: filesystem-specific information or "none".
		fmt.Fprintf(&buf, "none ")

		// (11) Superblock options. Only "ro/rw" is supported for now,
		// and is the same as the filesystem option.
		fmt.Fprintf(&buf, "%s\n", opts)
	})

	return []seqfile.SeqData{{Buf: buf.Bytes(), Handle: (*mountInfoFile)(nil)}}, 0
}

// mountsFile is used to implement /proc/[pid]/mountinfo.
//
// +stateify savable
type mountsFile struct {
	t *kernel.Task
}

// NeedsUpdate implements SeqSource.NeedsUpdate.
func (mf *mountsFile) NeedsUpdate(_ int64) bool {
	return true
}

// ReadSeqFileData implements SeqSource.ReadSeqFileData.
func (mf *mountsFile) ReadSeqFileData(ctx context.Context, handle seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if handle != nil {
		return nil, 0
	}

	var buf bytes.Buffer
	forEachMountSource(mf.t, func(mountPath string, m *fs.MountSource) {
		// Format:
		// <special device or remote filesystem> <mount point> <filesystem type> <mount options> <needs dump> <fsck order>
		//
		// We use the filesystem name as the first field, since there
		// is no real block device we can point to, and we also should
		// not expose anything about the remote filesystem.
		//
		// Only ro/rw option is supported for now.
		//
		// The "needs dump"and fsck flags are always 0, which is allowed.
		opts := "rw"
		if m.Flags.ReadOnly {
			opts = "ro"
		}
		name := "none"
		if m.Filesystem != nil {
			name = m.Filesystem.Name()
		}
		fmt.Fprintf(&buf, "%s %s %s %s %d %d\n", "none", mountPath, name, opts, 0, 0)
	})

	return []seqfile.SeqData{{Buf: buf.Bytes(), Handle: (*mountsFile)(nil)}}, 0
}
