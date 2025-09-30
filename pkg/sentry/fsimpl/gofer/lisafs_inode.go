// Copyright 2022 The gVisor Authors.
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
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func (fs *filesystem) handleAnameLisafs(ctx context.Context, rootInode lisafs.Inode) (lisafs.Inode, error) {
	if fs.opts.aname == "/" {
		return rootInode, nil
	}

	// Walk to the attach point from root inode. aname is always absolute.
	rootFD := fs.client.NewFD(rootInode.ControlFD)
	status, inodes, err := rootFD.WalkMultiple(ctx, strings.Split(fs.opts.aname, "/")[1:])
	if err != nil {
		return lisafs.Inode{}, err
	}

	// Close all intermediate FDs to the attach point.
	rootFD.Close(ctx, false /* flush */)
	numInodes := len(inodes)
	for i := 0; i < numInodes-1; i++ {
		curFD := fs.client.NewFD(inodes[i].ControlFD)
		curFD.Close(ctx, false /* flush */)
	}

	switch status {
	case lisafs.WalkSuccess:
		return inodes[numInodes-1], nil
	default:
		if numInodes > 0 {
			last := fs.client.NewFD(inodes[numInodes-1].ControlFD)
			last.Close(ctx, false /* flush */)
		}
		log.Warningf("initClient failed because walk to attach point %q failed: lisafs.WalkStatus = %v", fs.opts.aname, status)
		return lisafs.Inode{}, linuxerr.ENOENT
	}
}

// lisafsInode is a gofer inode implementation. It represents a inode backed
// by a lisafs connection.
//
// +stateify savable
type lisafsInode struct {
	inode

	// controlFD is used by lisafs to perform path based operations on this
	// dentry. controlFD is immutable.
	//
	// if !controlFD.Ok(), this dentry represents a synthetic file, i.e. a
	// file that does not exist on the remote filesystem. As of this writing, the
	// only files that can be synthetic are sockets, pipes, and directories.
	controlFD lisafs.ClientFD `state:"nosave"`

	// If this dentry represents a regular file or directory, readFDLisa is a
	// LISAFS FD used for reads by all regularFileFDs/directoryFDs representing
	// this dentry. readFDLisa is protected by dentry.handleMu.
	readFDLisa lisafs.ClientFD `state:"nosave"`

	// If this dentry represents a regular file, writeFDLisa is the LISAFS FD
	// used for writes by all regularFileFDs representing this dentry.
	// readFDLisa and writeFDLisa may or may not represent the same LISAFS FD.
	// Once either transitions from closed (Ok() == false) to open
	// (Ok() == true), it may be mutated with dentry.handleMu locked, but cannot
	// be closed until the dentry is destroyei. writeFDLisa is protected by
	// dentry.handleMu.
	writeFDLisa lisafs.ClientFD `state:"nosave"`
}

// newLisafsDentry serves two purposes:
//  1. newLisafsDentry creates a new dentry representing the given file. The dentry
//     initially has no references, but is not cached; it is the caller's
//     responsibility to set the dentry's reference count and/or call.
//     dentry.checkCachingLocked() as appropriate.
//  2. newLisafsDentry checks if there is a corresponding inode in the cache.
//     If not, it creates a new inode representing the given file and takes
//     ownership of controlFD.
//
// newLisafsDentry takes ownership of ino.
func (fs *filesystem) newLisafsDentry(ctx context.Context, ino *lisafs.Inode) (*dentry, error) {
	if ino.Stat.Mask&linux.STATX_TYPE == 0 {
		ctx.Warningf("can't create gofer.inode without file type")
		fs.client.CloseFD(ctx, ino.ControlFD, false /* flush */)
		return nil, linuxerr.EIO
	}
	if ino.Stat.Mode&linux.FileTypeMask == linux.ModeRegular && ino.Stat.Mask&linux.STATX_SIZE == 0 {
		ctx.Warningf("can't create regular file gofer.dentry without file size")
		fs.client.CloseFD(ctx, ino.ControlFD, false /* flush */)
		return nil, linuxerr.EIO
	}
	isDir := ino.Stat.Mode&linux.FileTypeMask == linux.ModeDirectory
	inoKey := inoKeyFromStatx(&ino.Stat)
	// Common case. Performance hack which is used to allocate the dentry
	// and its inode together in the heap. This will help reduce allocations and memory
	// fragmentation. This is more cache friendly too.
	// Obviously in case of hard link and if the inode already exists,
	// we just re-use the inode and heap allocate just the dentry struct.
	temp := struct {
		d dentry
		i lisafsInode
	}{}
	// Force new inode creation for directory inodes to avoid hard-linking directories.
	// This also avoids a correctness issue when a directory is bind-mounted on the host:
	// different paths (e.g., /mnt/ and /mnt/a/b/c if /mnt/a/b/c is a bind mount of /mnt/)
	// can return the same device ID and inode number from a stat call.
	temp.d.inode = fs.getOrCreateInode(inoKey /* dontCache = */, isDir,
		func() { fs.client.CloseFD(ctx, ino.ControlFD, false /* flush */) },
		func() *inode {
			temp.i = lisafsInode{
				inode: inode{
					fs:        fs,
					inoKey:    inoKey,
					ino:       fs.inoFromKey(inoKey),
					mode:      atomicbitops.FromUint32(uint32(ino.Stat.Mode)),
					uid:       atomicbitops.FromUint32(uint32(fs.opts.dfltuid)),
					gid:       atomicbitops.FromUint32(uint32(fs.opts.dfltgid)),
					blockSize: atomicbitops.FromUint32(hostarch.PageSize),
					readFD:    atomicbitops.FromInt32(-1),
					writeFD:   atomicbitops.FromInt32(-1),
					mmapFD:    atomicbitops.FromInt32(-1),
				},
				controlFD: fs.client.NewFD(ino.ControlFD),
			}
			temp.i.inode.init(&temp.i)
			inode := &temp.i.inode
			if ino.Stat.Mask&linux.STATX_UID != 0 {
				inode.uid = atomicbitops.FromUint32(dentryUID(lisafs.UID(ino.Stat.UID)))
			}
			if ino.Stat.Mask&linux.STATX_GID != 0 {
				inode.gid = atomicbitops.FromUint32(dentryGID(lisafs.GID(ino.Stat.GID)))
			}
			if ino.Stat.Mask&linux.STATX_SIZE != 0 {
				inode.size = atomicbitops.FromUint64(ino.Stat.Size)
			}
			if ino.Stat.Blksize != 0 {
				inode.blockSize = atomicbitops.FromUint32(ino.Stat.Blksize)
			}
			if ino.Stat.Mask&linux.STATX_ATIME != 0 {
				inode.atime = atomicbitops.FromInt64(dentryTimestamp(ino.Stat.Atime))
			} else {
				inode.atime = atomicbitops.FromInt64(fs.clock.Now().Nanoseconds())
			}
			if ino.Stat.Mask&linux.STATX_MTIME != 0 {
				inode.mtime = atomicbitops.FromInt64(dentryTimestamp(ino.Stat.Mtime))
			} else {
				inode.mtime = atomicbitops.FromInt64(fs.clock.Now().Nanoseconds())
			}
			if ino.Stat.Mask&linux.STATX_CTIME != 0 {
				inode.ctime = atomicbitops.FromInt64(dentryTimestamp(ino.Stat.Ctime))
			} else {
				// Approximate ctime with mtime if ctime isn't available.
				inode.ctime = atomicbitops.FromInt64(inode.mtime.Load())
			}
			if ino.Stat.Mask&linux.STATX_BTIME != 0 {
				inode.btime = atomicbitops.FromInt64(dentryTimestamp(ino.Stat.Btime))
			}

			if ino.Stat.Mask&linux.STATX_NLINK != 0 {
				inode.nlink = atomicbitops.FromUint32(ino.Stat.Nlink)
			} else {
				if isDir {
					inode.nlink = atomicbitops.FromUint32(2)
				} else {
					inode.nlink = atomicbitops.FromUint32(1)
				}
			}
			return inode
		})

	temp.d.init()
	fs.syncMu.Lock()
	fs.syncableDentries.PushBack(&temp.d.syncableListEntry)
	fs.syncMu.Unlock()
	return &temp.d, nil
}

func (i *lisafsInode) openHandle(ctx context.Context, flags uint32) (handle, error) {
	openFD, hostFD, err := i.controlFD.OpenAt(ctx, flags)
	if err != nil {
		return noHandle, err
	}
	return handle{
		fdLisa: i.controlFD.Client().NewFD(openFD),
		fd:     int32(hostFD),
	}, nil
}

func (i *lisafsInode) updateHandles(ctx context.Context, h handle, readable, writable bool) {
	// Switch to new LISAFS FDs. Note that the read, write and mmap host FDs are
	// updated separately.
	oldReadFD := lisafs.InvalidFDID
	if readable {
		oldReadFD = i.readFDLisa.ID()
		i.readFDLisa = h.fdLisa
	}
	oldWriteFD := lisafs.InvalidFDID
	if writable {
		oldWriteFD = i.writeFDLisa.ID()
		i.writeFDLisa = h.fdLisa
	}
	// NOTE(b/141991141): Close old FDs before making new fids visible (by
	// unlocking i.handleMu).
	if oldReadFD.Ok() {
		i.fs.client.CloseFD(ctx, oldReadFD, false /* flush */)
	}
	if oldWriteFD.Ok() && oldReadFD != oldWriteFD {
		i.fs.client.CloseFD(ctx, oldWriteFD, false /* flush */)
	}
}

// +checklocks:i.metadataMu
func (i *lisafsInode) updateMetadataLocked(ctx context.Context, h handle) error {
	handleMuRLocked := false
	if !h.fdLisa.Ok() {
		// Use open FDs in preferenece to the control FD. This may be significantly
		// more efficient in some implementations. Prefer a writable FD over a
		// readable one since some filesystem implementations may update a writable
		// FD's metadata after writes, without making metadata updates immediately
		// visible to read-only FDs representing the same file.
		i.handleMu.RLock()
		switch {
		case i.writeFDLisa.Ok():
			h.fdLisa = i.writeFDLisa
			handleMuRLocked = true
		case i.readFDLisa.Ok():
			h.fdLisa = i.readFDLisa
			handleMuRLocked = true
		default:
			h.fdLisa = i.controlFD
			i.handleMu.RUnlock()
		}
	}

	var stat linux.Statx
	err := h.fdLisa.StatTo(ctx, &stat)
	if handleMuRLocked {
		// handleMu must be released before updateMetadataFromStatLocked().
		i.handleMu.RUnlock() // +checklocksforce: complex case.
	}
	if err != nil {
		return err
	}
	i.updateMetadataFromStatxLocked(&stat)
	return nil
}

// updateMetadataFromStatxLocked is called to update d's metadata after an update
// from the remote filesystem.
// +checklocks:i.inode.metadataMu
func (i *lisafsInode) updateMetadataFromStatxLocked(stat *linux.Statx) {
	if stat.Mask&linux.STATX_TYPE != 0 {
		if got, want := stat.Mode&linux.FileTypeMask, i.inode.fileType(); uint32(got) != want {
			panic(fmt.Sprintf("lisafsInode file type changed from %#o to %#o", want, got))
		}
	}
	if stat.Mask&linux.STATX_MODE != 0 {
		i.inode.mode.Store(uint32(stat.Mode))
	}
	if stat.Mask&linux.STATX_UID != 0 {
		i.inode.uid.Store(dentryUID(lisafs.UID(stat.UID)))
	}
	if stat.Mask&linux.STATX_GID != 0 {
		i.inode.gid.Store(dentryGID(lisafs.GID(stat.GID)))
	}
	if stat.Blksize != 0 {
		i.inode.blockSize.Store(stat.Blksize)
	}
	// Don't override newer client-defined timestamps with old server-defined
	// ones.
	if stat.Mask&linux.STATX_ATIME != 0 && i.inode.atimeDirty.Load() == 0 {
		i.inode.atime.Store(dentryTimestamp(stat.Atime))
	}
	if stat.Mask&linux.STATX_MTIME != 0 && i.inode.mtimeDirty.Load() == 0 {
		i.inode.mtime.Store(dentryTimestamp(stat.Mtime))
	}
	if stat.Mask&linux.STATX_CTIME != 0 {
		i.inode.ctime.Store(dentryTimestamp(stat.Ctime))
	}
	if stat.Mask&linux.STATX_BTIME != 0 {
		i.inode.btime.Store(dentryTimestamp(stat.Btime))
	}
	if stat.Mask&linux.STATX_NLINK != 0 {
		i.inode.nlink.Store(stat.Nlink)
	}
	if stat.Mask&linux.STATX_SIZE != 0 {
		i.updateSizeLocked(stat.Size)
	}
}

func chmod(ctx context.Context, controlFD lisafs.ClientFD, mode uint16) error {
	setStat := linux.Statx{
		Mask: linux.STATX_MODE,
		Mode: mode,
	}
	_, failureErr, err := controlFD.SetStat(ctx, &setStat)
	if err != nil {
		return err
	}
	return failureErr
}

func (i *lisafsInode) destroy(ctx context.Context, d *dentry) {
	if i.readFDLisa.Ok() && i.readFDLisa.ID() != i.writeFDLisa.ID() {
		i.readFDLisa.Close(ctx, false /* flush */)
	}
	if i.writeFDLisa.Ok() {
		i.writeFDLisa.Close(ctx, false /* flush */)
	}
	if i.controlFD.Ok() {
		// Close the control FD. Propagate the Close RPCs immediately to the server
		// if the dentry being destroyed is a deleted regular file. This is to
		// release the disk space on remote immediately. This will flush the above
		// read/write lisa FDs as well.
		flushClose := d.isDeleted() && i.isRegularFile()
		i.controlFD.Close(ctx, flushClose)
	}
}

func (i *lisafsInode) getRemoteChild(ctx context.Context, name string) (*dentry, error) {
	childInode, err := i.controlFD.Walk(ctx, name)
	if err != nil {
		return nil, err
	}
	return i.fs.newLisafsDentry(ctx, &childInode)
}

// Preconditions:
//   - fs.renameMu must be locked.
//   - i.opMu must be locked.
//   - i.isDir().
//   - !rp.done() && rp.Component() is not "." or "..".
//
// Postcondition: The returned dentry is already cached appropriately.
func (i *lisafsInode) getRemoteChildAndWalkPathLocked(ctx context.Context, rp resolvingPath, ds **[]*dentry, d *dentry) (*dentry, error) {
	// Collect as many path components as possible to walk.
	var namesArr [16]string // arbitrarily sized array to help avoid slice allocation.
	names := namesArr[:0]
	rp.getComponents(func(name string) bool {
		if name == "." {
			return true
		}
		if name == ".." {
			return false
		}
		names = append(names, name)
		return true
	})
	// Walk as much of the path as possible in 1 RPC.
	_, inodes, err := i.controlFD.WalkMultiple(ctx, names)
	if err != nil {
		return nil, err
	}
	if len(inodes) == 0 {
		// i.opMu is locked. So a new child could not have appeared concurrently.
		// It should be safe to mark this as a negative entry.
		d.childrenMu.Lock()
		defer d.childrenMu.Unlock()
		d.cacheNegativeLookupLocked(names[0])
		return nil, linuxerr.ENOENT
	}

	// Add the walked inodes into the dentry tree.
	startParent := d
	curParent := startParent
	curParentLock := func() {
		if curParent != startParent {
			curParent.opMu.RLock()
		}
		curParent.childrenMu.Lock()
	}
	curParentUnlock := func() {
		curParent.childrenMu.Unlock()
		if curParent != startParent {
			curParent.opMu.RUnlock() // +checklocksforce: locked via curParentLock().
		}
	}
	var ret *dentry
	var dentryCreationErr error
	for i := range inodes {
		if dentryCreationErr != nil {
			d.inode.fs.client.CloseFD(ctx, inodes[i].ControlFD, false /* flush */)
			continue
		}

		curParentLock()
		// Did we race with another walk + cache operation?
		child, ok := curParent.children[names[i]] // +checklocksforce: locked via curParentLock()
		if ok && child != nil {
			// We raced. Clean up the new inode and proceed with
			// the cached child.
			d.inode.fs.client.CloseFD(ctx, inodes[i].ControlFD, false /* flush */)
		} else {
			// Create and cache the new dentry.
			var err error
			child, err = d.inode.fs.newLisafsDentry(ctx, &inodes[i])
			if err != nil {
				dentryCreationErr = err
				curParentUnlock()
				continue
			}
			curParent.cacheNewChildLocked(child, names[i]) // +checklocksforce: locked via curParentLock().
		}
		curParentUnlock()

		// For now, child has 0 references, so our caller should call
		// child.checkCachingLocked(). curParent gained a ref so we should also
		// call curParent.checkCachingLocked() so it can be removed from the cache
		// if needed. We only do that for the first iteration because all
		// subsequent parents would have already been added to ds.
		if i == 0 {
			*ds = appendDentry(*ds, curParent)
		}
		*ds = appendDentry(*ds, child)
		curParent = child
		if i == 0 {
			ret = child
		}
	}
	return ret, dentryCreationErr
}

func (i *lisafsInode) newChildDentry(ctx context.Context, childIno *lisafs.Inode, childName string) (*dentry, error) {
	child, err := i.fs.newLisafsDentry(ctx, childIno)
	if err != nil {
		if err := i.controlFD.UnlinkAt(ctx, childName, 0 /* flags */); err != nil {
			log.Warningf("failed to clean up created child %q after newDentry() failed: %v", childName, err)
		}
	}
	return child, err
}

func (i *lisafsInode) mknod(ctx context.Context, name string, creds *auth.Credentials, opts *vfs.MknodOptions) (*dentry, error) {
	if _, ok := opts.Endpoint.(transport.HostBoundEndpoint); !ok {
		childInode, err := i.controlFD.MknodAt(ctx, name, opts.Mode, lisafs.UID(creds.EffectiveKUID), lisafs.GID(creds.EffectiveKGID), opts.DevMinor, opts.DevMajor)
		if err != nil {
			return nil, err
		}
		return i.newChildDentry(ctx, &childInode, name)
	}

	// This mknod(2) is coming from unix bind(2), as opts.Endpoint is set.
	sockType := opts.Endpoint.(transport.Endpoint).Type()
	childInode, boundSocketFD, err := i.controlFD.BindAt(ctx, sockType, name, opts.Mode, lisafs.UID(creds.EffectiveKUID), lisafs.GID(creds.EffectiveKGID))
	if err != nil {
		return nil, err
	}
	hbep := opts.Endpoint.(transport.HostBoundEndpoint)
	if err := hbep.SetBoundSocketFD(ctx, boundSocketFD); err != nil {
		if err := i.controlFD.UnlinkAt(ctx, name, 0 /* flags */); err != nil {
			log.Warningf("failed to clean up socket which was created by BindAt RPC: %v", err)
		}
		i.fs.client.CloseFD(ctx, childInode.ControlFD, false /* flush */)
		return nil, err
	}
	child, err := i.newChildDentry(ctx, &childInode, name)
	if err != nil {
		hbep.ResetBoundSocketFD(ctx)
		return nil, err
	}
	// Set the endpoint on the newly created child dentry, and take the
	// corresponding extra dentry reference.
	child.inode.endpoint = opts.Endpoint
	child.IncRef()
	return child, nil
}

func (i *lisafsInode) link(ctx context.Context, target *lisafsInode, name string) (*dentry, error) {
	linkInode, err := i.controlFD.LinkAt(ctx, target.controlFD.ID(), name)
	if err != nil {
		return nil, err
	}
	return i.newChildDentry(ctx, &linkInode, name)
}

func (i *lisafsInode) mkdir(ctx context.Context, name string, mode linux.FileMode, uid auth.KUID, gid auth.KGID, createDentry bool) (*dentry, error) {
	childDirInode, err := i.controlFD.MkdirAt(ctx, name, mode, lisafs.UID(uid), lisafs.GID(gid))
	if err != nil {
		return nil, err
	}
	if !createDentry {
		return nil, nil
	}
	return i.newChildDentry(ctx, &childDirInode, name)
}

func (i *lisafsInode) symlink(ctx context.Context, name, target string, creds *auth.Credentials) (*dentry, error) {
	symlinkInode, err := i.controlFD.SymlinkAt(ctx, name, target, lisafs.UID(creds.EffectiveKUID), lisafs.GID(creds.EffectiveKGID))
	if err != nil {
		return nil, err
	}
	return i.newChildDentry(ctx, &symlinkInode, name)
}

func (i *lisafsInode) openCreate(ctx context.Context, name string, flags uint32, mode linux.FileMode, uid auth.KUID, gid auth.KGID, createDentry bool) (*dentry, handle, error) {
	ino, openFD, hostFD, err := i.controlFD.OpenCreateAt(ctx, name, flags, mode, lisafs.UID(uid), lisafs.GID(gid))
	if err != nil {
		return nil, noHandle, err
	}

	h := handle{
		fdLisa: i.fs.client.NewFD(openFD),
		fd:     int32(hostFD),
	}
	if !createDentry {
		return nil, h, nil
	}
	child, err := i.fs.newLisafsDentry(ctx, &ino)
	if err != nil {
		h.close(ctx)
		return nil, noHandle, err
	}
	return child, h, nil
}

// lisafsGetdentsCount is the number of bytes of dirents to read from the
// server in each Getdents RPC. This value is consistent with vfs1 client.
const lisafsGetdentsCount = int32(64 * 1024)

// Preconditions:
//   - getDirents may not be called concurrently with another getDirents call.
func (i *lisafsInode) getDirentsLocked(ctx context.Context, recordDirent func(name string, key inoKey, dType uint8)) error {
	// shouldSeek0 indicates whether the server should SEEK to 0 before reading
	// directory entries.
	shouldSeek0 := true
	for {
		count := lisafsGetdentsCount
		if shouldSeek0 {
			// See lisafs.Getdents64Req.Count.
			count = -count
			shouldSeek0 = false
		}
		dirents, err := i.readFDLisa.Getdents64(ctx, count)
		if err != nil {
			return err
		}
		if len(dirents) == 0 {
			return nil
		}
		for i := range dirents {
			name := string(dirents[i].Name)
			if name == "." || name == ".." {
				continue
			}
			recordDirent(name, inoKey{
				ino:      uint64(dirents[i].Ino),
				devMinor: uint32(dirents[i].DevMinor),
				devMajor: uint32(dirents[i].DevMajor),
			}, uint8(dirents[i].Type))
		}
	}
}

func flush(ctx context.Context, fd lisafs.ClientFD) error {
	if fd.Ok() {
		return fd.Flush(ctx)
	}
	return nil
}

func (i *lisafsInode) statfs(ctx context.Context) (linux.Statfs, error) {
	var statFS lisafs.StatFS
	if err := i.controlFD.StatFSTo(ctx, &statFS); err != nil {
		return linux.Statfs{}, err
	}
	return linux.Statfs{
		BlockSize:       statFS.BlockSize,
		FragmentSize:    statFS.BlockSize,
		Blocks:          statFS.Blocks,
		BlocksFree:      statFS.BlocksFree,
		BlocksAvailable: statFS.BlocksAvailable,
		Files:           statFS.Files,
		FilesFree:       statFS.FilesFree,
		NameLength:      statFS.NameLength,
	}, nil
}

func (i *lisafsInode) restoreInode(ctx context.Context, inode *lisafs.Inode, opts *vfs.CompleteRestoreOptions, d *dentry) error {
	i.controlFD = i.fs.client.NewFD(inode.ControlFD)

	// Gofers do not preserve inoKey across checkpoint/restore, so:
	//
	//	- We must assume that the remote filesystem did not change in a way that
	//		would invalidate dentries, since we can't revalidate dentries by
	//		checking inoKey.
	//
	//	- We need to associate the new inoKey with the existing i.ino.
	i.inoKey = inoKeyFromStatx(&inode.Stat)
	i.fs.inoMu.Lock()
	i.fs.inoByKey[i.inoKey] = i.ino
	i.fs.inoMu.Unlock()
	i.fs.inodeMu.Lock()
	i.fs.inodeByKey[i.inoKey] = &i.inode
	i.fs.inodeMu.Unlock()

	// Check metadata stability before updating metadata.
	i.metadataMu.Lock()
	defer i.metadataMu.Unlock()
	if i.isRegularFile() {
		if opts.ValidateFileSizes {
			if inode.Stat.Mask&linux.STATX_SIZE == 0 {
				return vfs.ErrCorruption{Err: fmt.Errorf("gofer.dentry(%q).restoreFile: file size validation failed: file size not available", genericDebugPathname(i.fs, d))}
			}
			if i.size.RacyLoad() != inode.Stat.Size {
				return vfs.ErrCorruption{Err: fmt.Errorf("gofer.dentry(%q).restoreFile: file size validation failed: size changed from %d to %d", genericDebugPathname(i.fs, d), i.size.Load(), inode.Stat.Size)}
			}
		}
		if opts.ValidateFileModificationTimestamps {
			if inode.Stat.Mask&linux.STATX_MTIME == 0 {
				return vfs.ErrCorruption{Err: fmt.Errorf("gofer.dentry(%q).restoreFile: mtime validation failed: mtime not available", genericDebugPathname(i.fs, d))}
			}
			if want := dentryTimestamp(inode.Stat.Mtime); i.mtime.RacyLoad() != want {
				return vfs.ErrCorruption{Err: fmt.Errorf("gofer.dentry(%q).restoreFile: mtime validation failed: mtime changed from %+v to %+v", genericDebugPathname(i.fs, d), linux.NsecToStatxTimestamp(i.mtime.RacyLoad()), linux.NsecToStatxTimestamp(want))}
			}
		}
	}
	if !i.cachedMetadataAuthoritative() {
		i.updateMetadataFromStatxLocked(&inode.Stat)
	}

	if rw, ok := i.fs.savedDentryRW[d]; ok {
		if err := d.ensureSharedHandle(ctx, rw.read, rw.write, false /* trunc */); err != nil {
			return fmt.Errorf("failed to restore file handles (read=%t, write=%t) for %q: %w", rw.read, rw.write, genericDebugPathname(i.fs, d), err)
		}
	}

	return nil
}

// doRevalidationLisafs stats all dentries in `state`. It will update or
// invalidate dentries in the cache based on the result.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - InteropModeShared is in effect.
func doRevalidationLisafs(ctx context.Context, vfsObj *vfs.VirtualFilesystem, state *revalidateState, ds **[]*dentry) error {
	start := state.start.inode.impl.(*lisafsInode)

	// Populate state.names.
	state.names = state.names[:0] // For sanity.
	if state.refreshStart {
		state.names = append(state.names, "")
	}
	for _, d := range state.dentries {
		state.names = append(state.names, d.name)
	}

	// Lock metadata on all dentries *before* getting attributes for them.
	if state.refreshStart {
		start.inode.metadataMu.Lock()
		defer start.inode.metadataMu.Unlock()
	}
	for _, d := range state.dentries {
		d.inode.metadataMu.Lock()
	}
	// lastUnlockedDentry keeps track of the dentries in state.dentries that have
	// already had their metadataMu unlocked. Avoid defer unlock in the loop
	// above to avoid heap allocation.
	lastUnlockedDentry := -1
	defer func() {
		// Advance to the first unevaluated dentry and unlock the remaining
		// dentries.
		for lastUnlockedDentry++; lastUnlockedDentry < len(state.dentries); lastUnlockedDentry++ {
			state.dentries[lastUnlockedDentry].inode.metadataMu.Unlock()
		}
	}()

	// Make WalkStat RPC.
	stats, err := start.controlFD.WalkStat(ctx, state.names)
	if err != nil {
		return err
	}

	if state.refreshStart {
		if len(stats) > 0 {
			// First dentry is where the search is starting, just update attributes
			// since it cannot be replaced.
			start.updateMetadataFromStatxLocked(&stats[0]) // +checklocksforce: see above.
			stats = stats[1:]
		}
	}

	for i := 0; i < len(state.dentries); i++ {
		d := state.dentries[i]
		found := i < len(stats)

		// Note that synthetic dentries will always fail this comparison check.
		if !found ||
			d.inode.inoKey != inoKeyFromStatx(&stats[i]) ||
			(stats[i].Mask&linux.STATX_TYPE != 0 && uint32(stats[i].Mode&linux.FileTypeMask) != d.inode.fileType()) {
			d.inode.metadataMu.Unlock()
			lastUnlockedDentry = i
			if !found && d.inode.isSynthetic() {
				// We have a synthetic file, and no remote file has arisen to replace
				// it.
				return nil
			}
			// The file at this path has changed or no longer exists. Mark the
			// dentry invalidated.
			d.invalidate(ctx, vfsObj, ds)
			return nil
		}

		// The file at this path hasn't changed. Just update cached metadata.
		d.inode.impl.(*lisafsInode).updateMetadataFromStatxLocked(&stats[i]) // +checklocksforce: see above.
		d.inode.metadataMu.Unlock()
		lastUnlockedDentry = i
	}
	return nil
}
