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
	"sort"
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// LINT.IfChange

// forEachMountSource runs f for the process root mount and  each mount that is a
// descendant of the root.
func forEachMount(t *kernel.Task, fn func(string, *fs.Mount)) {
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

	mnt := t.MountNamespace().FindMount(rootDir)
	if mnt == nil {
		// Has it just been unmounted?
		return
	}
	ms := t.MountNamespace().AllMountsUnder(mnt)
	sort.Slice(ms, func(i, j int) bool {
		return ms[i].ID < ms[j].ID
	})
	for _, m := range ms {
		mroot := m.Root()
		if mroot == nil {
			continue // No longer valid.
		}
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
	forEachMount(mif.t, func(mountPath string, m *fs.Mount) {
		mroot := m.Root()
		if mroot == nil {
			return // No longer valid.
		}
		defer mroot.DecRef()

		// Format:
		// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
		// (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)

		// (1) MountSource ID.
		fmt.Fprintf(&buf, "%d ", m.ID)

		// (2)  Parent ID (or this ID if there is no parent).
		pID := m.ID
		if !m.IsRoot() && !m.IsUndo() {
			pID = m.ParentID
		}
		fmt.Fprintf(&buf, "%d ", pID)

		// (3) Major:Minor device ID. We don't have a superblock, so we
		// just use the root inode device number.
		sa := mroot.Inode.StableAttr
		fmt.Fprintf(&buf, "%d:%d ", sa.DeviceFileMajor, sa.DeviceFileMinor)

		// (4) Root: the pathname of the directory in the filesystem
		// which forms the root of this mount.
		//
		// NOTE(b/78135857): This will always be "/" until we implement
		// bind mounts.
		fmt.Fprintf(&buf, "/ ")

		// (5) Mount point (relative to process root).
		fmt.Fprintf(&buf, "%s ", mountPath)

		// (6) Mount options.
		flags := mroot.Inode.MountSource.Flags
		opts := "rw"
		if flags.ReadOnly {
			opts = "ro"
		}
		if flags.NoAtime {
			opts += ",noatime"
		}
		if flags.NoExec {
			opts += ",noexec"
		}
		fmt.Fprintf(&buf, "%s ", opts)

		// (7) Optional fields: zero or more fields of the form "tag[:value]".
		// (8) Separator: the end of the optional fields is marked by a single hyphen.
		fmt.Fprintf(&buf, "- ")

		// (9) Filesystem type.
		fmt.Fprintf(&buf, "%s ", mroot.Inode.MountSource.FilesystemType)

		// (10) Mount source: filesystem-specific information or "none".
		fmt.Fprintf(&buf, "none ")

		// (11) Superblock options, and final newline.
		fmt.Fprintf(&buf, "%s\n", superBlockOpts(mountPath, mroot.Inode.MountSource))
	})

	return []seqfile.SeqData{{Buf: buf.Bytes(), Handle: (*mountInfoFile)(nil)}}, 0
}

func superBlockOpts(mountPath string, msrc *fs.MountSource) string {
	// gVisor doesn't (yet) have a concept of super block options, so we
	// use the ro/rw bit from the mount flag.
	opts := "rw"
	if msrc.Flags.ReadOnly {
		opts = "ro"
	}

	// NOTE(b/147673608): If the mount is a cgroup, we also need to include
	// the cgroup name in the options. For now we just read that from the
	// path.
	//
	// TODO(gvisor.dev/issue/190): Once gVisor has full cgroup support, we
	// should get this value from the cgroup itself, and not rely on the
	// path.
	if msrc.FilesystemType == "cgroup" {
		splitPath := strings.Split(mountPath, "/")
		cgroupType := splitPath[len(splitPath)-1]
		opts += "," + cgroupType
	}
	return opts
}

// mountsFile is used to implement /proc/[pid]/mounts.
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
	forEachMount(mf.t, func(mountPath string, m *fs.Mount) {
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
		root := m.Root()
		if root == nil {
			return // No longer valid.
		}
		defer root.DecRef()

		flags := root.Inode.MountSource.Flags
		opts := "rw"
		if flags.ReadOnly {
			opts = "ro"
		}
		fmt.Fprintf(&buf, "%s %s %s %s %d %d\n", "none", mountPath, root.Inode.MountSource.FilesystemType, opts, 0, 0)
	})

	return []seqfile.SeqData{{Buf: buf.Bytes(), Handle: (*mountsFile)(nil)}}, 0
}

// LINT.ThenChange(../../fsimpl/proc/tasks_files.go)
