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

package gofer

import (
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// getattr returns the 9p attributes of the p9.File. On success, Mode, Size, and RDev
// are guaranteed to be masked as valid.
func getattr(ctx context.Context, file contextFile) (p9.QID, p9.AttrMask, p9.Attr, error) {
	// Retrieve attributes over the wire.
	qid, valid, attr, err := file.getAttr(ctx, p9.AttrMaskAll())
	if err != nil {
		return qid, valid, attr, err
	}

	// Require mode, size, and raw device id.
	if !valid.Mode || !valid.Size || !valid.RDev {
		return qid, valid, attr, syscall.EIO
	}

	return qid, valid, attr, nil
}

func unstable(ctx context.Context, valid p9.AttrMask, pattr p9.Attr, mounter fs.FileOwner, client *p9.Client) fs.UnstableAttr {
	return fs.UnstableAttr{
		Size:             int64(pattr.Size),
		Usage:            int64(pattr.Size),
		Perms:            perms(valid, pattr, client),
		Owner:            owner(mounter, valid, pattr),
		AccessTime:       atime(ctx, valid, pattr),
		ModificationTime: mtime(ctx, valid, pattr),
		StatusChangeTime: ctime(ctx, valid, pattr),
		Links:            links(valid, pattr),
	}
}

func perms(valid p9.AttrMask, pattr p9.Attr, client *p9.Client) fs.FilePermissions {
	if pattr.Mode.IsDir() && !p9.VersionSupportsMultiUser(client.Version()) {
		// If user and group permissions bits are not supplied, use
		// "other" bits to supplement them.
		//
		// Older Gofer's fake directories only have "other" permission,
		// but will often be accessed via user or group permissions.
		if pattr.Mode&0770 == 0 {
			other := pattr.Mode & 07
			pattr.Mode = pattr.Mode | other<<3 | other<<6
		}
	}
	return fs.FilePermsFromP9(pattr.Mode)
}

func owner(mounter fs.FileOwner, valid p9.AttrMask, pattr p9.Attr) fs.FileOwner {
	// Unless the file returned its UID and GID, it belongs to the mounting
	// task's EUID/EGID.
	owner := mounter
	if valid.UID {
		owner.UID = auth.KUID(pattr.UID)
	}
	if valid.GID {
		owner.GID = auth.KGID(pattr.GID)
	}
	return owner
}

// bsize returns a block size from 9p attributes.
func bsize(pattr p9.Attr) int64 {
	if pattr.BlockSize > 0 {
		return int64(pattr.BlockSize)
	}
	// Some files may have no clue of their block size. Better not to report
	// something misleading or buggy and have a safe default.
	return usermem.PageSize
}

// ntype returns an fs.InodeType from 9p attributes.
func ntype(pattr p9.Attr) fs.InodeType {
	switch {
	case pattr.Mode.IsNamedPipe():
		return fs.Pipe
	case pattr.Mode.IsDir():
		return fs.Directory
	case pattr.Mode.IsSymlink():
		return fs.Symlink
	case pattr.Mode.IsCharacterDevice():
		return fs.CharacterDevice
	case pattr.Mode.IsBlockDevice():
		return fs.BlockDevice
	case pattr.Mode.IsSocket():
		return fs.Socket
	case pattr.Mode.IsRegular():
		fallthrough
	default:
		return fs.RegularFile
	}
}

// ctime returns a change time from 9p attributes.
func ctime(ctx context.Context, valid p9.AttrMask, pattr p9.Attr) ktime.Time {
	if valid.CTime {
		return ktime.FromUnix(int64(pattr.CTimeSeconds), int64(pattr.CTimeNanoSeconds))
	}
	// Approximate ctime with mtime if ctime isn't available.
	return mtime(ctx, valid, pattr)
}

// atime returns an access time from 9p attributes.
func atime(ctx context.Context, valid p9.AttrMask, pattr p9.Attr) ktime.Time {
	if valid.ATime {
		return ktime.FromUnix(int64(pattr.ATimeSeconds), int64(pattr.ATimeNanoSeconds))
	}
	return ktime.NowFromContext(ctx)
}

// mtime returns a modification time from 9p attributes.
func mtime(ctx context.Context, valid p9.AttrMask, pattr p9.Attr) ktime.Time {
	if valid.MTime {
		return ktime.FromUnix(int64(pattr.MTimeSeconds), int64(pattr.MTimeNanoSeconds))
	}
	return ktime.NowFromContext(ctx)
}

// links returns a hard link count from 9p attributes.
func links(valid p9.AttrMask, pattr p9.Attr) uint64 {
	// For gofer file systems that support link count (such as a local file gofer),
	// we return the link count reported by the underlying file system.
	if valid.NLink {
		return pattr.NLink
	}

	// This node is likely backed by a file system that doesn't support links.
	// We could readdir() and count children directories to provide an accurate
	// link count. However this may be expensive since the gofer may be backed by remote
	// storage. Instead, simply return 2 links for directories and 1 for everything else
	// since no one relies on an accurate link count for gofer-based file systems.
	switch ntype(pattr) {
	case fs.Directory:
		return 2
	default:
		return 1
	}
}
