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

// lisafsDentry is a gofer dentry implementation. It represents a dentry backed
// by a lisafs connection.
//
// +stateify savable
type lisafsDentry struct {
	dentry

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
	// be closed until the dentry is destroyed. writeFDLisa is protected by
	// dentry.handleMu.
	writeFDLisa lisafs.ClientFD `state:"nosave"`
}

// newLisafsDentry creates a new dentry representing the given file. The dentry
// initially has no references, but is not cached; it is the caller's
// responsibility to set the dentry's reference count and/or call
// dentry.checkCachingLocked() as appropriate.
// newLisafsDentry takes ownership of ino.
func (fs *filesystem) newLisafsDentry(ctx context.Context, ino *lisafs.Inode) (*dentry, error) {
	if ino.Stat.Mask&linux.STATX_TYPE == 0 {
		ctx.Warningf("can't create gofer.dentry without file type")
		fs.client.CloseFD(ctx, ino.ControlFD, false /* flush */)
		return nil, linuxerr.EIO
	}
	if ino.Stat.Mode&linux.FileTypeMask == linux.ModeRegular && ino.Stat.Mask&linux.STATX_SIZE == 0 {
		ctx.Warningf("can't create regular file gofer.dentry without file size")
		fs.client.CloseFD(ctx, ino.ControlFD, false /* flush */)
		return nil, linuxerr.EIO
	}

	inoKey := inoKeyFromStatx(&ino.Stat)
	d := &lisafsDentry{
		dentry: dentry{
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
	if ino.Stat.Mask&linux.STATX_UID != 0 {
		d.uid = atomicbitops.FromUint32(dentryUID(lisafs.UID(ino.Stat.UID)))
	}
	if ino.Stat.Mask&linux.STATX_GID != 0 {
		d.gid = atomicbitops.FromUint32(dentryGID(lisafs.GID(ino.Stat.GID)))
	}
	if ino.Stat.Mask&linux.STATX_SIZE != 0 {
		d.size = atomicbitops.FromUint64(ino.Stat.Size)
	}
	if ino.Stat.Blksize != 0 {
		d.blockSize = atomicbitops.FromUint32(ino.Stat.Blksize)
	}
	if ino.Stat.Mask&linux.STATX_ATIME != 0 {
		d.atime = atomicbitops.FromInt64(dentryTimestamp(ino.Stat.Atime))
	} else {
		d.atime = atomicbitops.FromInt64(fs.clock.Now().Nanoseconds())
	}
	if ino.Stat.Mask&linux.STATX_MTIME != 0 {
		d.mtime = atomicbitops.FromInt64(dentryTimestamp(ino.Stat.Mtime))
	} else {
		d.mtime = atomicbitops.FromInt64(fs.clock.Now().Nanoseconds())
	}
	if ino.Stat.Mask&linux.STATX_CTIME != 0 {
		d.ctime = atomicbitops.FromInt64(dentryTimestamp(ino.Stat.Ctime))
	} else {
		// Approximate ctime with mtime if ctime isn't available.
		d.ctime = atomicbitops.FromInt64(d.mtime.Load())
	}
	if ino.Stat.Mask&linux.STATX_BTIME != 0 {
		d.btime = atomicbitops.FromInt64(dentryTimestamp(ino.Stat.Btime))
	}
	if ino.Stat.Mask&linux.STATX_NLINK != 0 {
		d.nlink = atomicbitops.FromUint32(ino.Stat.Nlink)
	} else {
		if ino.Stat.Mode&linux.FileTypeMask == linux.ModeDirectory {
			d.nlink = atomicbitops.FromUint32(2)
		} else {
			d.nlink = atomicbitops.FromUint32(1)
		}
	}
	d.dentry.init(d)
	fs.syncMu.Lock()
	fs.syncableDentries.PushBack(&d.syncableListEntry)
	fs.syncMu.Unlock()
	return &d.dentry, nil
}

func (d *lisafsDentry) openHandle(ctx context.Context, flags uint32) (handle, error) {
	openFD, hostFD, err := d.controlFD.OpenAt(ctx, flags)
	if err != nil {
		return noHandle, err
	}
	return handle{
		fdLisa: d.controlFD.Client().NewFD(openFD),
		fd:     int32(hostFD),
	}, nil
}

func (d *lisafsDentry) updateHandles(ctx context.Context, h handle, readable, writable bool) {
	// Switch to new LISAFS FDs. Note that the read, write and mmap host FDs are
	// updated separately.
	oldReadFD := lisafs.InvalidFDID
	if readable {
		oldReadFD = d.readFDLisa.ID()
		d.readFDLisa = h.fdLisa
	}
	oldWriteFD := lisafs.InvalidFDID
	if writable {
		oldWriteFD = d.writeFDLisa.ID()
		d.writeFDLisa = h.fdLisa
	}
	// NOTE(b/141991141): Close old FDs before making new fids visible (by
	// unlocking d.handleMu).
	if oldReadFD.Ok() {
		d.fs.client.CloseFD(ctx, oldReadFD, false /* flush */)
	}
	if oldWriteFD.Ok() && oldReadFD != oldWriteFD {
		d.fs.client.CloseFD(ctx, oldWriteFD, false /* flush */)
	}
}

// Precondition: d.metadataMu must be locked.
//
// +checklocks:d.metadataMu
func (d *lisafsDentry) updateMetadataLocked(ctx context.Context, h handle) error {
	handleMuRLocked := false
	if !h.fdLisa.Ok() {
		// Use open FDs in preferenece to the control FD. This may be significantly
		// more efficient in some implementations. Prefer a writable FD over a
		// readable one since some filesystem implementations may update a writable
		// FD's metadata after writes, without making metadata updates immediately
		// visible to read-only FDs representing the same file.
		d.handleMu.RLock()
		switch {
		case d.writeFDLisa.Ok():
			h.fdLisa = d.writeFDLisa
			handleMuRLocked = true
		case d.readFDLisa.Ok():
			h.fdLisa = d.readFDLisa
			handleMuRLocked = true
		default:
			h.fdLisa = d.controlFD
			d.handleMu.RUnlock()
		}
	}

	var stat linux.Statx
	err := h.fdLisa.StatTo(ctx, &stat)
	if handleMuRLocked {
		// handleMu must be released before updateMetadataFromStatLocked().
		d.handleMu.RUnlock() // +checklocksforce: complex case.
	}
	if err != nil {
		return err
	}
	d.updateMetadataFromStatxLocked(&stat)
	return nil
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

func (d *lisafsDentry) destroy(ctx context.Context) {
	if d.readFDLisa.Ok() && d.readFDLisa.ID() != d.writeFDLisa.ID() {
		d.readFDLisa.Close(ctx, false /* flush */)
	}
	if d.writeFDLisa.Ok() {
		d.writeFDLisa.Close(ctx, false /* flush */)
	}
	if d.controlFD.Ok() {
		// Close the control FD. Propagate the Close RPCs immediately to the server
		// if the dentry being destroyed is a deleted regular file. This is to
		// release the disk space on remote immediately. This will flush the above
		// read/write lisa FDs as well.
		flushClose := d.isDeleted() && d.isRegularFile()
		d.controlFD.Close(ctx, flushClose)
	}
}

func (d *lisafsDentry) getRemoteChild(ctx context.Context, name string) (*dentry, error) {
	childInode, err := d.controlFD.Walk(ctx, name)
	if err != nil {
		return nil, err
	}
	return d.fs.newLisafsDentry(ctx, &childInode)
}

// Preconditions:
//   - fs.renameMu must be locked.
//   - d.opMu must be locked.
//   - d.isDir().
//   - !rp.done() && rp.Component() is not "." or "..".
//
// Postcondition: The returned dentry is already cached appropriately.
func (d *lisafsDentry) getRemoteChildAndWalkPathLocked(ctx context.Context, rp resolvingPath, ds **[]*dentry) (*dentry, error) {
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
	_, inodes, err := d.controlFD.WalkMultiple(ctx, names)
	if err != nil {
		return nil, err
	}
	if len(inodes) == 0 {
		// d.opMu is locked. So a new child could not have appeared concurrently.
		// It should be safe to mark this as a negative entry.
		d.childrenMu.Lock()
		defer d.childrenMu.Unlock()
		d.cacheNegativeLookupLocked(names[0])
		return nil, linuxerr.ENOENT
	}

	// Add the walked inodes into the dentry tree.
	startParent := &d.dentry
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
			d.fs.client.CloseFD(ctx, inodes[i].ControlFD, false /* flush */)
			continue
		}

		curParentLock()
		// Did we race with another walk + cache operation?
		child, ok := curParent.children[names[i]] // +checklocksforce: locked via curParentLock()
		if ok && child != nil {
			// We raced. Clean up the new inode and proceed with
			// the cached child.
			d.fs.client.CloseFD(ctx, inodes[i].ControlFD, false /* flush */)
		} else {
			// Create and cache the new dentry.
			var err error
			child, err = d.fs.newLisafsDentry(ctx, &inodes[i])
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

func (d *lisafsDentry) newChildDentry(ctx context.Context, childIno *lisafs.Inode, childName string) (*dentry, error) {
	child, err := d.fs.newLisafsDentry(ctx, childIno)
	if err != nil {
		if err := d.controlFD.UnlinkAt(ctx, childName, 0 /* flags */); err != nil {
			log.Warningf("failed to clean up created child %s after newLisafsDentry() failed: %v", childName, err)
		}
	}
	return child, err
}

func (d *lisafsDentry) mknod(ctx context.Context, name string, creds *auth.Credentials, opts *vfs.MknodOptions) (*dentry, error) {
	if _, ok := opts.Endpoint.(transport.HostBoundEndpoint); !ok {
		childInode, err := d.controlFD.MknodAt(ctx, name, opts.Mode, lisafs.UID(creds.EffectiveKUID), lisafs.GID(creds.EffectiveKGID), opts.DevMinor, opts.DevMajor)
		if err != nil {
			return nil, err
		}
		return d.newChildDentry(ctx, &childInode, name)
	}

	// This mknod(2) is coming from unix bind(2), as opts.Endpoint is set.
	sockType := opts.Endpoint.(transport.Endpoint).Type()
	childInode, boundSocketFD, err := d.controlFD.BindAt(ctx, sockType, name, opts.Mode, lisafs.UID(creds.EffectiveKUID), lisafs.GID(creds.EffectiveKGID))
	if err != nil {
		return nil, err
	}
	hbep := opts.Endpoint.(transport.HostBoundEndpoint)
	if err := hbep.SetBoundSocketFD(ctx, boundSocketFD); err != nil {
		if err := d.controlFD.UnlinkAt(ctx, name, 0 /* flags */); err != nil {
			log.Warningf("failed to clean up socket which was created by BindAt RPC: %v", err)
		}
		d.fs.client.CloseFD(ctx, childInode.ControlFD, false /* flush */)
		return nil, err
	}
	child, err := d.newChildDentry(ctx, &childInode, name)
	if err != nil {
		hbep.ResetBoundSocketFD(ctx)
		return nil, err
	}
	// Set the endpoint on the newly created child dentry.
	child.endpoint = opts.Endpoint
	return child, nil
}

func (d *lisafsDentry) link(ctx context.Context, target *lisafsDentry, name string) (*dentry, error) {
	linkInode, err := d.controlFD.LinkAt(ctx, target.controlFD.ID(), name)
	if err != nil {
		return nil, err
	}
	// TODO(gvisor.dev/issue/6739): Hard linked dentries should share the same
	// inode fields.
	return d.newChildDentry(ctx, &linkInode, name)
}

func (d *lisafsDentry) mkdir(ctx context.Context, name string, mode linux.FileMode, uid auth.KUID, gid auth.KGID) (*dentry, error) {
	childDirInode, err := d.controlFD.MkdirAt(ctx, name, mode, lisafs.UID(uid), lisafs.GID(gid))
	if err != nil {
		return nil, err
	}
	return d.newChildDentry(ctx, &childDirInode, name)
}

func (d *lisafsDentry) symlink(ctx context.Context, name, target string, creds *auth.Credentials) (*dentry, error) {
	symlinkInode, err := d.controlFD.SymlinkAt(ctx, name, target, lisafs.UID(creds.EffectiveKUID), lisafs.GID(creds.EffectiveKGID))
	if err != nil {
		return nil, err
	}
	return d.newChildDentry(ctx, &symlinkInode, name)
}

func (d *lisafsDentry) openCreate(ctx context.Context, name string, flags uint32, mode linux.FileMode, uid auth.KUID, gid auth.KGID) (*dentry, handle, error) {
	ino, openFD, hostFD, err := d.controlFD.OpenCreateAt(ctx, name, flags, mode, lisafs.UID(uid), lisafs.GID(gid))
	if err != nil {
		return nil, noHandle, err
	}

	h := handle{
		fdLisa: d.fs.client.NewFD(openFD),
		fd:     int32(hostFD),
	}
	child, err := d.fs.newLisafsDentry(ctx, &ino)
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
func (d *lisafsDentry) getDirentsLocked(ctx context.Context, recordDirent func(name string, key inoKey, dType uint8)) error {
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
		dirents, err := d.readFDLisa.Getdents64(ctx, count)
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

func (d *lisafsDentry) statfs(ctx context.Context) (linux.Statfs, error) {
	var statFS lisafs.StatFS
	if err := d.controlFD.StatFSTo(ctx, &statFS); err != nil {
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

func (d *lisafsDentry) restoreFile(ctx context.Context, inode *lisafs.Inode, opts *vfs.CompleteRestoreOptions) error {
	d.controlFD = d.fs.client.NewFD(inode.ControlFD)

	// Gofers do not preserve inoKey across checkpoint/restore, so:
	//
	//	- We must assume that the remote filesystem did not change in a way that
	//		would invalidate dentries, since we can't revalidate dentries by
	//		checking inoKey.
	//
	//	- We need to associate the new inoKey with the existing d.ino.
	d.inoKey = inoKeyFromStatx(&inode.Stat)
	d.fs.inoMu.Lock()
	d.fs.inoByKey[d.inoKey] = d.ino
	d.fs.inoMu.Unlock()

	// Check metadata stability before updating metadata.
	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()
	if d.isRegularFile() {
		if opts.ValidateFileSizes {
			if inode.Stat.Mask&linux.STATX_SIZE == 0 {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: file size validation failed: file size not available", genericDebugPathname(&d.dentry))}
			}
			if d.size.RacyLoad() != inode.Stat.Size {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: file size validation failed: size changed from %d to %d", genericDebugPathname(&d.dentry), d.size.Load(), inode.Stat.Size)}
			}
		}
		if opts.ValidateFileModificationTimestamps {
			if inode.Stat.Mask&linux.STATX_MTIME == 0 {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: mtime validation failed: mtime not available", genericDebugPathname(&d.dentry))}
			}
			if want := dentryTimestamp(inode.Stat.Mtime); d.mtime.RacyLoad() != want {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: mtime validation failed: mtime changed from %+v to %+v", genericDebugPathname(&d.dentry), linux.NsecToStatxTimestamp(d.mtime.RacyLoad()), linux.NsecToStatxTimestamp(want))}
			}
		}
	}
	if !d.cachedMetadataAuthoritative() {
		d.updateMetadataFromStatxLocked(&inode.Stat)
	}

	if rw, ok := d.fs.savedDentryRW[&d.dentry]; ok {
		if err := d.ensureSharedHandle(ctx, rw.read, rw.write, false /* trunc */); err != nil {
			return err
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
	start := state.start.impl.(*lisafsDentry)

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
		start.metadataMu.Lock()
		defer start.metadataMu.Unlock()
	}
	for _, d := range state.dentries {
		d.metadataMu.Lock()
	}
	// lastUnlockedDentry keeps track of the dentries in state.dentries that have
	// already had their metadataMu unlocked. Avoid defer unlock in the loop
	// above to avoid heap allocation.
	lastUnlockedDentry := -1
	defer func() {
		// Advance to the first unevaluated dentry and unlock the remaining
		// dentries.
		for lastUnlockedDentry++; lastUnlockedDentry < len(state.dentries); lastUnlockedDentry++ {
			state.dentries[lastUnlockedDentry].metadataMu.Unlock()
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
		// Advance lastUnlockedDentry. It is the responsibility of this for loop
		// block to unlock d.metadataMu.
		lastUnlockedDentry = i

		// Note that synthetic dentries will always fail this comparison check.
		if !found || d.inoKey != inoKeyFromStatx(&stats[i]) {
			d.metadataMu.Unlock()
			if !found && d.isSynthetic() {
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
		d.impl.(*lisafsDentry).updateMetadataFromStatxLocked(&stats[i]) // +checklocksforce: see above.
		d.metadataMu.Unlock()
	}
	return nil
}
