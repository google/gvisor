// Copyright 2020 The gVisor Authors.
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

package verity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/merkletree"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	// All files should be read-only.
	return nil
}

var dentrySlicePool = sync.Pool{
	New: func() interface{} {
		ds := make([]*dentry, 0, 4) // arbitrary non-zero initial capacity
		return &ds
	},
}

func appendDentry(ds *[]*dentry, d *dentry) *[]*dentry {
	if ds == nil {
		ds = dentrySlicePool.Get().(*[]*dentry)
	}
	*ds = append(*ds, d)
	return ds
}

// Preconditions: ds != nil.
func putDentrySlice(ds *[]*dentry) {
	// Allow dentries to be GC'd.
	for i := range *ds {
		(*ds)[i] = nil
	}
	*ds = (*ds)[:0]
	dentrySlicePool.Put(ds)
}

// renameMuRUnlockAndCheckDrop calls fs.renameMu.RUnlock(), then calls
// dentry.checkDropLocked on all dentries in *ds with fs.renameMu locked for
// writing.
//
// ds is a pointer-to-pointer since defer evaluates its arguments immediately,
// but dentry slices are allocated lazily, and it's much easier to say "defer
// fs.renameMuRUnlockAndCheckDrop(&ds)" than "defer func() {
// fs.renameMuRUnlockAndCheckDrop(ds) }()" to work around this.
// +checklocksrelease:fs.renameMu
func (fs *filesystem) renameMuRUnlockAndCheckDrop(ctx context.Context, ds **[]*dentry) {
	fs.renameMu.RUnlock()
	if *ds == nil {
		return
	}
	if len(**ds) != 0 {
		fs.renameMu.Lock()
		for _, d := range **ds {
			d.checkDropLocked(ctx)
		}
		fs.renameMu.Unlock()
	}
	putDentrySlice(*ds)
}

// +checklocksrelease:fs.renameMu
func (fs *filesystem) renameMuUnlockAndCheckDrop(ctx context.Context, ds **[]*dentry) {
	if *ds == nil {
		fs.renameMu.Unlock()
		return
	}
	for _, d := range **ds {
		d.checkDropLocked(ctx)
	}
	fs.renameMu.Unlock()
	putDentrySlice(*ds)
}

// stepLocked resolves rp.Component() to an existing file, starting from the
// given directory.
//
// Dentries which may have a reference count of zero, and which therefore
// should be dropped once traversal is complete, are appended to ds.
//
// Preconditions:
// * fs.renameMu must be locked.
// * d.dirMu must be locked.
// * !rp.Done().
func (fs *filesystem) stepLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry, mayFollowSymlinks bool, ds **[]*dentry) (*dentry, error) {
	if !d.isDir() {
		return nil, linuxerr.ENOTDIR
	}

	if err := d.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, err
	}

afterSymlink:
	name := rp.Component()
	if name == "." {
		rp.Advance()
		return d, nil
	}
	if name == ".." {
		if isRoot, err := rp.CheckRoot(ctx, &d.vfsd); err != nil {
			return nil, err
		} else if isRoot || d.parent == nil {
			rp.Advance()
			return d, nil
		}
		if err := rp.CheckMount(ctx, &d.parent.vfsd); err != nil {
			return nil, err
		}
		rp.Advance()
		return d.parent, nil
	}
	child, err := fs.getChildLocked(ctx, d, name, ds)
	if err != nil {
		return nil, err
	}
	if err := rp.CheckMount(ctx, &child.vfsd); err != nil {
		return nil, err
	}
	if child.isSymlink() && mayFollowSymlinks && rp.ShouldFollowSymlink() {
		target, err := child.readlink(ctx)
		if err != nil {
			return nil, err
		}
		if err := rp.HandleSymlink(target); err != nil {
			return nil, err
		}
		goto afterSymlink // don't check the current directory again
	}
	rp.Advance()
	return child, nil
}

// verifyChildLocked verifies the hash of child against the already verified
// hash of the parent to ensure the child is expected.  verifyChild triggers a
// sentry panic if unexpected modifications to the file system are detected. In
// ErrorOnViolation mode it returns a syserror instead.
//
// Preconditions:
// * fs.renameMu must be locked.
// * d.dirMu must be locked.
func (fs *filesystem) verifyChildLocked(ctx context.Context, parent *dentry, child *dentry) (*dentry, error) {
	vfsObj := fs.vfsfs.VirtualFilesystem()

	// Get the path to the child dentry. This is only used to provide path
	// information in failure case.
	childPath, err := vfsObj.PathnameWithDeleted(ctx, child.fs.rootDentry.lowerVD, child.lowerVD)
	if err != nil {
		return nil, err
	}

	fs.verityMu.RLock()
	defer fs.verityMu.RUnlock()
	// Read the offset of the child from the extended attributes of the
	// corresponding Merkle tree file.
	// This is the offset of the hash for child in its parent's Merkle tree
	// file.
	off, err := vfsObj.GetXattrAt(ctx, fs.creds, &vfs.PathOperation{
		Root:  child.lowerMerkleVD,
		Start: child.lowerMerkleVD,
	}, &vfs.GetXattrOptions{
		Name: merkleOffsetInParentXattr,
		Size: sizeOfStringInt32,
	})

	// The Merkle tree file for the child should have been created and
	// contains the expected xattrs. If the file or the xattr does not
	// exist, it indicates unexpected modifications to the file system.
	if linuxerr.Equals(linuxerr.ENOENT, err) || linuxerr.Equals(linuxerr.ENODATA, err) {
		return nil, fs.alertIntegrityViolation(fmt.Sprintf("Failed to get xattr %s for %s: %v", merkleOffsetInParentXattr, childPath, err))
	}
	if err != nil {
		return nil, err
	}
	// The offset xattr should be an integer. If it's not, it indicates
	// unexpected modifications to the file system.
	offset, err := strconv.Atoi(off)
	if err != nil {
		return nil, fs.alertIntegrityViolation(fmt.Sprintf("Failed to convert xattr %s for %s to int: %v", merkleOffsetInParentXattr, childPath, err))
	}

	// Open parent Merkle tree file to read and verify child's hash.
	parentMerkleFD, err := vfsObj.OpenAt(ctx, fs.creds, &vfs.PathOperation{
		Root:  parent.lowerMerkleVD,
		Start: parent.lowerMerkleVD,
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	})

	// The parent Merkle tree file should have been created. If it's
	// missing, it indicates an unexpected modification to the file system.
	if linuxerr.Equals(linuxerr.ENOENT, err) {
		return nil, fs.alertIntegrityViolation(fmt.Sprintf("Failed to open parent Merkle file for %s: %v", childPath, err))
	}
	if err != nil {
		return nil, err
	}

	defer parentMerkleFD.DecRef(ctx)

	// dataSize is the size of raw data for the Merkle tree. For a file,
	// dataSize is the size of the whole file. For a directory, dataSize is
	// the size of all its children's hashes.
	dataSize, err := parentMerkleFD.GetXattr(ctx, &vfs.GetXattrOptions{
		Name: merkleSizeXattr,
		Size: sizeOfStringInt32,
	})

	// The Merkle tree file for the child should have been created and
	// contains the expected xattrs. If the file or the xattr does not
	// exist, it indicates unexpected modifications to the file system.
	if linuxerr.Equals(linuxerr.ENOENT, err) || linuxerr.Equals(linuxerr.ENODATA, err) {
		return nil, fs.alertIntegrityViolation(fmt.Sprintf("Failed to get xattr %s for %s: %v", merkleSizeXattr, childPath, err))
	}
	if err != nil {
		return nil, err
	}

	// The dataSize xattr should be an integer. If it's not, it indicates
	// unexpected modifications to the file system.
	parentSize, err := strconv.Atoi(dataSize)
	if err != nil {
		return nil, fs.alertIntegrityViolation(fmt.Sprintf("Failed to convert xattr %s for %s to int: %v", merkleSizeXattr, childPath, err))
	}

	fdReader := FileReadWriteSeeker{
		FD:  parentMerkleFD,
		Ctx: ctx,
	}

	parentStat, err := vfsObj.StatAt(ctx, fs.creds, &vfs.PathOperation{
		Root:  parent.lowerVD,
		Start: parent.lowerVD,
	}, &vfs.StatOptions{})
	if linuxerr.Equals(linuxerr.ENOENT, err) {
		return nil, fs.alertIntegrityViolation(fmt.Sprintf("Failed to get parent stat for %s: %v", childPath, err))
	}
	if err != nil {
		return nil, err
	}

	// Since we are verifying against a directory Merkle tree, buf should
	// contain the hash of the children in the parent Merkle tree when
	// Verify returns with success.
	var buf bytes.Buffer
	parent.hashMu.RLock()
	_, err = merkletree.Verify(&merkletree.VerifyParams{
		Out:                   &buf,
		File:                  &fdReader,
		Tree:                  &fdReader,
		Size:                  int64(parentSize),
		Name:                  parent.name,
		Mode:                  uint32(parentStat.Mode),
		UID:                   parentStat.UID,
		GID:                   parentStat.GID,
		Children:              parent.childrenList,
		HashAlgorithms:        fs.alg.toLinuxHashAlg(),
		ReadOffset:            int64(offset),
		ReadSize:              int64(merkletree.DigestSize(fs.alg.toLinuxHashAlg())),
		Expected:              parent.hash,
		DataAndTreeInSameFile: true,
	})
	parent.hashMu.RUnlock()
	if err != nil && err != io.EOF {
		return nil, fs.alertIntegrityViolation(fmt.Sprintf("Verification for %s failed: %v", childPath, err))
	}

	// Cache child hash when it's verified the first time.
	child.hashMu.Lock()
	if len(child.hash) == 0 {
		child.hash = buf.Bytes()
	}
	child.hashMu.Unlock()
	return child, nil
}

// verifyStatAndChildrenLocked verifies the stat and children names against the
// verified hash. The mode/uid/gid and childrenNames of the file is cached
// after verified.
//
// Preconditions: d.dirMu must be locked.
func (fs *filesystem) verifyStatAndChildrenLocked(ctx context.Context, d *dentry, stat linux.Statx) error {
	vfsObj := fs.vfsfs.VirtualFilesystem()

	// Get the path to the child dentry. This is only used to provide path
	// information in failure case.
	childPath, err := vfsObj.PathnameWithDeleted(ctx, d.fs.rootDentry.lowerVD, d.lowerVD)
	if err != nil {
		return err
	}

	fs.verityMu.RLock()
	defer fs.verityMu.RUnlock()

	fd, err := vfsObj.OpenAt(ctx, fs.creds, &vfs.PathOperation{
		Root:  d.lowerMerkleVD,
		Start: d.lowerMerkleVD,
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	})
	if linuxerr.Equals(linuxerr.ENOENT, err) {
		return fs.alertIntegrityViolation(fmt.Sprintf("Failed to open merkle file for %s: %v", childPath, err))
	}
	if err != nil {
		return err
	}

	defer fd.DecRef(ctx)

	merkleSize, err := fd.GetXattr(ctx, &vfs.GetXattrOptions{
		Name: merkleSizeXattr,
		Size: sizeOfStringInt32,
	})

	if linuxerr.Equals(linuxerr.ENODATA, err) {
		return fs.alertIntegrityViolation(fmt.Sprintf("Failed to get xattr %s for merkle file of %s: %v", merkleSizeXattr, childPath, err))
	}
	if err != nil {
		return err
	}

	size, err := strconv.Atoi(merkleSize)
	if err != nil {
		return fs.alertIntegrityViolation(fmt.Sprintf("Failed to convert xattr %s for %s to int: %v", merkleSizeXattr, childPath, err))
	}

	if d.isDir() && len(d.childrenNames) == 0 {
		childrenOffString, err := fd.GetXattr(ctx, &vfs.GetXattrOptions{
			Name: childrenOffsetXattr,
			Size: sizeOfStringInt32,
		})

		if linuxerr.Equals(linuxerr.ENODATA, err) {
			return fs.alertIntegrityViolation(fmt.Sprintf("Failed to get xattr %s for merkle file of %s: %v", childrenOffsetXattr, childPath, err))
		}
		if err != nil {
			return err
		}
		childrenOffset, err := strconv.Atoi(childrenOffString)
		if err != nil {
			return fs.alertIntegrityViolation(fmt.Sprintf("Failed to convert xattr %s to int: %v", childrenOffsetXattr, err))
		}

		childrenSizeString, err := fd.GetXattr(ctx, &vfs.GetXattrOptions{
			Name: childrenSizeXattr,
			Size: sizeOfStringInt32,
		})

		if linuxerr.Equals(linuxerr.ENODATA, err) {
			return fs.alertIntegrityViolation(fmt.Sprintf("Failed to get xattr %s for merkle file of %s: %v", childrenSizeXattr, childPath, err))
		}
		if err != nil {
			return err
		}
		childrenSize, err := strconv.Atoi(childrenSizeString)
		if err != nil {
			return fs.alertIntegrityViolation(fmt.Sprintf("Failed to convert xattr %s to int: %v", childrenSizeXattr, err))
		}

		childrenNames := make([]byte, childrenSize)
		if _, err := fd.PRead(ctx, usermem.BytesIOSequence(childrenNames), int64(childrenOffset), vfs.ReadOptions{}); err != nil {
			return fs.alertIntegrityViolation(fmt.Sprintf("Failed to read children map for %s: %v", childPath, err))
		}

		if err := json.Unmarshal(childrenNames, &d.childrenNames); err != nil {
			return fs.alertIntegrityViolation(fmt.Sprintf("Failed to deserialize childrenNames of %s: %v", childPath, err))
		}
	}

	fdReader := FileReadWriteSeeker{
		FD:  fd,
		Ctx: ctx,
	}

	var buf bytes.Buffer
	d.hashMu.RLock()

	d.generateChildrenList()

	params := &merkletree.VerifyParams{
		Out:            &buf,
		Tree:           &fdReader,
		Size:           int64(size),
		Name:           d.name,
		Mode:           uint32(stat.Mode),
		UID:            stat.UID,
		GID:            stat.GID,
		Children:       d.childrenList,
		HashAlgorithms: fs.alg.toLinuxHashAlg(),
		ReadOffset:     0,
		// Set read size to 0 so only the metadata is verified.
		ReadSize:              0,
		Expected:              d.hash,
		DataAndTreeInSameFile: false,
	}
	d.hashMu.RUnlock()
	if atomic.LoadUint32(&d.mode)&linux.S_IFMT == linux.S_IFDIR {
		params.DataAndTreeInSameFile = true
	}

	if d.isSymlink() {
		target, err := vfsObj.ReadlinkAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  d.lowerVD,
			Start: d.lowerVD,
		})
		if err != nil {
			return err
		}
		params.SymlinkTarget = target
	}

	if _, err := merkletree.Verify(params); err != nil && err != io.EOF {
		return fs.alertIntegrityViolation(fmt.Sprintf("Verification stat for %s failed: %v", childPath, err))
	}
	d.mode = uint32(stat.Mode)
	d.uid = stat.UID
	d.gid = stat.GID
	d.size = uint32(size)
	d.symlinkTarget = params.SymlinkTarget
	return nil
}

// Preconditions:
// * fs.renameMu must be locked.
// * parent.dirMu must be locked.
func (fs *filesystem) getChildLocked(ctx context.Context, parent *dentry, name string, ds **[]*dentry) (*dentry, error) {
	if child, ok := parent.children[name]; ok {
		// If verity is enabled on child, we should check again whether
		// the file and the corresponding Merkle tree are as expected,
		// in order to catch deletion/renaming after the last time it's
		// accessed.
		if child.verityEnabled() {
			vfsObj := fs.vfsfs.VirtualFilesystem()
			// Get the path to the child dentry. This is only used
			// to provide path information in failure case.
			path, err := vfsObj.PathnameWithDeleted(ctx, child.fs.rootDentry.lowerVD, child.lowerVD)
			if err != nil {
				return nil, err
			}

			childVD, err := parent.getLowerAt(ctx, vfsObj, name)
			if linuxerr.Equals(linuxerr.ENOENT, err) {
				// The file was previously accessed. If the
				// file does not exist now, it indicates an
				// unexpected modification to the file system.
				return nil, fs.alertIntegrityViolation(fmt.Sprintf("Target file %s is expected but missing", path))
			}
			if err != nil {
				return nil, err
			}
			defer childVD.DecRef(ctx)

			childMerkleVD, err := parent.getLowerAt(ctx, vfsObj, merklePrefix+name)
			// The Merkle tree file was previous accessed. If it
			// does not exist now, it indicates an unexpected
			// modification to the file system.
			if linuxerr.Equals(linuxerr.ENOENT, err) {
				return nil, fs.alertIntegrityViolation(fmt.Sprintf("Expected Merkle file for target %s but none found", path))
			}
			if err != nil {
				return nil, err
			}

			defer childMerkleVD.DecRef(ctx)
		}

		// If enabling verification on files/directories is not allowed
		// during runtime, all cached children are already verified. If
		// runtime enable is allowed and the parent directory is
		// enabled, we should verify the child hash here because it may
		// be cached before enabled.
		if fs.allowRuntimeEnable {
			if parent.verityEnabled() {
				if _, err := fs.verifyChildLocked(ctx, parent, child); err != nil {
					return nil, err
				}
			}
			if child.verityEnabled() {
				vfsObj := fs.vfsfs.VirtualFilesystem()
				mask := uint32(linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID)
				stat, err := vfsObj.StatAt(ctx, fs.creds, &vfs.PathOperation{
					Root:  child.lowerVD,
					Start: child.lowerVD,
				}, &vfs.StatOptions{
					Mask: mask,
				})
				if err != nil {
					return nil, err
				}
				if err := fs.verifyStatAndChildrenLocked(ctx, child, stat); err != nil {
					return nil, err
				}
			}
		}
		return child, nil
	}
	child, err := fs.lookupAndVerifyLocked(ctx, parent, name)
	if err != nil {
		return nil, err
	}
	if parent.children == nil {
		parent.children = make(map[string]*dentry)
	}
	parent.children[name] = child
	// child's refcount is initially 0, so it may be dropped after traversal.
	*ds = appendDentry(*ds, child)
	return child, nil
}

// Preconditions:
// * fs.renameMu must be locked.
// * parent.dirMu must be locked.
func (fs *filesystem) lookupAndVerifyLocked(ctx context.Context, parent *dentry, name string) (*dentry, error) {
	vfsObj := fs.vfsfs.VirtualFilesystem()

	if parent.verityEnabled() {
		if _, ok := parent.childrenNames[name]; !ok {
			return nil, linuxerr.ENOENT
		}
	}

	parentPath, err := vfsObj.PathnameWithDeleted(ctx, parent.fs.rootDentry.lowerVD, parent.lowerVD)
	if err != nil {
		return nil, err
	}

	childVD, err := parent.getLowerAt(ctx, vfsObj, name)
	if parent.verityEnabled() && linuxerr.Equals(linuxerr.ENOENT, err) {
		return nil, fs.alertIntegrityViolation(fmt.Sprintf("file %s expected but not found", parentPath+"/"+name))
	}
	if err != nil {
		return nil, err
	}

	// The dentry needs to be cleaned up if any error occurs. IncRef will be
	// called if a verity child dentry is successfully created.
	defer childVD.DecRef(ctx)

	childMerkleVD, err := parent.getLowerAt(ctx, vfsObj, merklePrefix+name)
	if err != nil {
		if linuxerr.Equals(linuxerr.ENOENT, err) {
			if parent.verityEnabled() {
				return nil, fs.alertIntegrityViolation(fmt.Sprintf("Merkle file for %s expected but not found", parentPath+"/"+name))
			}
			childMerkleFD, err := vfsObj.OpenAt(ctx, fs.creds, &vfs.PathOperation{
				Root:  parent.lowerVD,
				Start: parent.lowerVD,
				Path:  fspath.Parse(merklePrefix + name),
			}, &vfs.OpenOptions{
				Flags: linux.O_RDWR | linux.O_CREAT,
				Mode:  0644,
			})
			if err != nil {
				return nil, err
			}
			childMerkleFD.DecRef(ctx)
			childMerkleVD, err = parent.getLowerAt(ctx, vfsObj, merklePrefix+name)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	// The dentry needs to be cleaned up if any error occurs. IncRef will be
	// called if a verity child dentry is successfully created.
	defer childMerkleVD.DecRef(ctx)

	mask := uint32(linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID)
	stat, err := vfsObj.StatAt(ctx, fs.creds, &vfs.PathOperation{
		Root:  childVD,
		Start: childVD,
	}, &vfs.StatOptions{
		Mask: mask,
	})
	if err != nil {
		return nil, err
	}

	child := fs.newDentry()
	child.lowerVD = childVD
	child.lowerMerkleVD = childMerkleVD

	// Increase the reference for both childVD and childMerkleVD as they are
	// held by child. If this function fails and the child is destroyed, the
	// references will be decreased in destroyLocked.
	childVD.IncRef()
	childMerkleVD.IncRef()

	child.name = name

	child.mode = uint32(stat.Mode)
	child.uid = stat.UID
	child.gid = stat.GID
	child.childrenNames = make(map[string]struct{})

	// Verify child hash. This should always be performed unless in
	// allowRuntimeEnable mode and the parent directory hasn't been enabled
	// yet.
	if parent.verityEnabled() {
		if _, err := fs.verifyChildLocked(ctx, parent, child); err != nil {
			child.destroyLocked(ctx)
			return nil, err
		}
	}
	if child.verityEnabled() {
		if err := fs.verifyStatAndChildrenLocked(ctx, child, stat); err != nil {
			child.destroyLocked(ctx)
			return nil, err
		}
	}

	parent.IncRef()
	child.parent = parent

	return child, nil
}

// walkParentDirLocked resolves all but the last path component of rp to an
// existing directory, starting from the given directory (which is usually
// rp.Start().Impl().(*dentry)). It does not check that the returned directory
// is searchable by the provider of rp.
//
// Preconditions:
// * fs.renameMu must be locked.
// * !rp.Done().
func (fs *filesystem) walkParentDirLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry, ds **[]*dentry) (*dentry, error) {
	for !rp.Final() {
		d.dirMu.Lock()
		next, err := fs.stepLocked(ctx, rp, d, true /* mayFollowSymlinks */, ds)
		d.dirMu.Unlock()
		if err != nil {
			return nil, err
		}
		d = next
	}
	if !d.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

// resolveLocked resolves rp to an existing file.
//
// Preconditions: fs.renameMu must be locked.
func (fs *filesystem) resolveLocked(ctx context.Context, rp *vfs.ResolvingPath, ds **[]*dentry) (*dentry, error) {
	d := rp.Start().Impl().(*dentry)
	for !rp.Done() {
		d.dirMu.Lock()
		next, err := fs.stepLocked(ctx, rp, d, true /* mayFollowSymlinks */, ds)
		d.dirMu.Unlock()
		if err != nil {
			return nil, err
		}
		d = next
	}
	if rp.MustBeDir() && !d.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

// AccessAt implements vfs.Filesystem.Impl.AccessAt.
func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	// Verity file system is read-only.
	if ats&vfs.MayWrite != 0 {
		return linuxerr.EROFS
	}
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return err
	}
	return d.checkPermissions(creds, ats)
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}
	if opts.CheckSearchable {
		if !d.isDir() {
			return nil, linuxerr.ENOTDIR
		}
		if err := d.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
			return nil, err
		}
	}
	d.IncRef()
	return &d.vfsd, nil
}

// GetParentDentryAt implements vfs.FilesystemImpl.GetParentDentryAt.
func (fs *filesystem) GetParentDentryAt(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	start := rp.Start().Impl().(*dentry)
	d, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return nil, err
	}
	d.IncRef()
	return &d.vfsd, nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	// Verity file system is read-only.
	return linuxerr.EROFS
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	// Verity file system is read-only.
	return linuxerr.EROFS
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	// Verity file system is read-only.
	return linuxerr.EROFS
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// Verity fs is read-only.
	if opts.Flags&(linux.O_WRONLY|linux.O_CREAT) != 0 {
		return nil, linuxerr.EROFS
	}

	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)

	start := rp.Start().Impl().(*dentry)
	if rp.Done() {
		return start.openLocked(ctx, rp, &opts)
	}

afterTrailingSymlink:
	parent, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return nil, err
	}

	// Check for search permission in the parent directory.
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, err
	}

	// Open existing child or follow symlink.
	parent.dirMu.Lock()
	child, err := fs.stepLocked(ctx, rp, parent, false /*mayFollowSymlinks*/, &ds)
	parent.dirMu.Unlock()
	if err != nil {
		return nil, err
	}
	if child.isSymlink() && rp.ShouldFollowSymlink() {
		target, err := child.readlink(ctx)
		if err != nil {
			return nil, err
		}
		if err := rp.HandleSymlink(target); err != nil {
			return nil, err
		}
		start = parent
		goto afterTrailingSymlink
	}
	return child.openLocked(ctx, rp, &opts)
}

// Preconditions: fs.renameMu must be locked.
func (d *dentry) openLocked(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	// Users should not open the Merkle tree files. Those are for verity fs
	// use only.
	if strings.Contains(d.name, merklePrefix) {
		return nil, linuxerr.EPERM
	}
	ats := vfs.AccessTypesForOpenFlags(opts)
	if err := d.checkPermissions(rp.Credentials(), ats); err != nil {
		return nil, err
	}

	// Verity fs is read-only.
	if ats&vfs.MayWrite != 0 {
		return nil, linuxerr.EROFS
	}

	// Get the path to the target file. This is only used to provide path
	// information in failure case.
	path, err := d.fs.vfsfs.VirtualFilesystem().PathnameWithDeleted(ctx, d.fs.rootDentry.lowerVD, d.lowerVD)
	if err != nil {
		return nil, err
	}

	tmpOpts := *opts

	// Open the lowerFD with O_PATH if a symlink is opened for verity.
	if tmpOpts.Flags&linux.O_NOFOLLOW != 0 && d.isSymlink() {
		tmpOpts.Flags |= linux.O_PATH
	}

	// Open the file in the underlying file system.
	lowerFD, err := rp.VirtualFilesystem().OpenAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  d.lowerVD,
		Start: d.lowerVD,
	}, &tmpOpts)

	// The file should exist, as we succeeded in finding its dentry. If it's
	// missing, it indicates an unexpected modification to the file system.
	if err != nil {
		if linuxerr.Equals(linuxerr.ENOENT, err) {
			return nil, d.fs.alertIntegrityViolation(fmt.Sprintf("File %s expected but not found", path))
		}
		return nil, err
	}

	// lowerFD needs to be cleaned up if any error occurs. IncRef will be
	// called if a verity FD is successfully created.
	defer lowerFD.DecRef(ctx)

	// Open the Merkle tree file corresponding to the current file/directory
	// to be used later for verifying Read/Walk.
	merkleReader, err := rp.VirtualFilesystem().OpenAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  d.lowerMerkleVD,
		Start: d.lowerMerkleVD,
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	})

	// The Merkle tree file should exist, as we succeeded in finding its
	// dentry. If it's missing, it indicates an unexpected modification to
	// the file system.
	if err != nil {
		if linuxerr.Equals(linuxerr.ENOENT, err) {
			return nil, d.fs.alertIntegrityViolation(fmt.Sprintf("Merkle file for %s expected but not found", path))
		}
		return nil, err
	}

	// merkleReader needs to be cleaned up if any error occurs. IncRef will
	// be called if a verity FD is successfully created.
	defer merkleReader.DecRef(ctx)

	lowerFDOpts := lowerFD.Options()
	var merkleWriter *vfs.FileDescription
	var parentMerkleWriter *vfs.FileDescription

	// Only open the Merkle tree files for write if in allowRuntimeEnable
	// mode.
	if d.fs.allowRuntimeEnable {
		merkleWriter, err = rp.VirtualFilesystem().OpenAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  d.lowerMerkleVD,
			Start: d.lowerMerkleVD,
		}, &vfs.OpenOptions{
			Flags: linux.O_WRONLY | linux.O_APPEND,
		})
		if err != nil {
			if linuxerr.Equals(linuxerr.ENOENT, err) {
				return nil, d.fs.alertIntegrityViolation(fmt.Sprintf("Merkle file for %s expected but not found", path))
			}
			return nil, err
		}
		// merkleWriter is cleaned up if any error occurs. IncRef will
		// be called if a verity FD is created successfully.
		defer merkleWriter.DecRef(ctx)

		if d.parent != nil {
			parentMerkleWriter, err = rp.VirtualFilesystem().OpenAt(ctx, d.fs.creds, &vfs.PathOperation{
				Root:  d.parent.lowerMerkleVD,
				Start: d.parent.lowerMerkleVD,
			}, &vfs.OpenOptions{
				Flags: linux.O_WRONLY | linux.O_APPEND,
			})
			if err != nil {
				if linuxerr.Equals(linuxerr.ENOENT, err) {
					parentPath, _ := d.fs.vfsfs.VirtualFilesystem().PathnameWithDeleted(ctx, d.fs.rootDentry.lowerVD, d.parent.lowerVD)
					return nil, d.fs.alertIntegrityViolation(fmt.Sprintf("Merkle file for %s expected but not found", parentPath))
				}
				return nil, err
			}
			// parentMerkleWriter is cleaned up if any error occurs. IncRef
			// will be called if a verity FD is created successfully.
			defer parentMerkleWriter.DecRef(ctx)
		}
	}

	fd := &fileDescription{
		d:                  d,
		lowerFD:            lowerFD,
		merkleReader:       merkleReader,
		merkleWriter:       merkleWriter,
		parentMerkleWriter: parentMerkleWriter,
		isDir:              d.isDir(),
	}

	if err := fd.vfsfd.Init(fd, opts.Flags, rp.Mount(), &d.vfsd, &lowerFDOpts); err != nil {
		return nil, err
	}
	lowerFD.IncRef()
	merkleReader.IncRef()
	if merkleWriter != nil {
		merkleWriter.IncRef()
	}
	if parentMerkleWriter != nil {
		parentMerkleWriter.IncRef()
	}
	return &fd.vfsfd, err
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return "", err
	}
	return d.readlink(ctx)
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	// Verity file system is read-only.
	return linuxerr.EROFS
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	// Verity file system is read-only.
	return linuxerr.EROFS
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	// Verity file system is read-only.
	return linuxerr.EROFS
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return linux.Statx{}, err
	}

	var stat linux.Statx
	stat, err = fs.vfsfs.VirtualFilesystem().StatAt(ctx, fs.creds, &vfs.PathOperation{
		Root:  d.lowerVD,
		Start: d.lowerVD,
	}, &opts)
	if err != nil {
		return linux.Statx{}, err
	}
	d.dirMu.Lock()
	if d.verityEnabled() {
		if err := fs.verifyStatAndChildrenLocked(ctx, d, stat); err != nil {
			return linux.Statx{}, err
		}
	}
	d.dirMu.Unlock()
	return stat, nil
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	// TODO(b/159261227): Implement StatFSAt.
	return linux.Statfs{}, nil
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	// Verity file system is read-only.
	return linuxerr.EROFS
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	// Verity file system is read-only.
	return linuxerr.EROFS
}

// BoundEndpointAt implements vfs.FilesystemImpl.BoundEndpointAt.
func (fs *filesystem) BoundEndpointAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	if _, err := fs.resolveLocked(ctx, rp, &ds); err != nil {
		return nil, err
	}
	return nil, linuxerr.ECONNREFUSED
}

// ListXattrAt implements vfs.FilesystemImpl.ListXattrAt.
func (fs *filesystem) ListXattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}
	lowerVD := d.lowerVD
	return fs.vfsfs.VirtualFilesystem().ListXattrAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  lowerVD,
		Start: lowerVD,
	}, size)
}

// GetXattrAt implements vfs.FilesystemImpl.GetXattrAt.
func (fs *filesystem) GetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetXattrOptions) (string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return "", err
	}
	lowerVD := d.lowerVD
	return fs.vfsfs.VirtualFilesystem().GetXattrAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  lowerVD,
		Start: lowerVD,
	}, &opts)
}

// SetXattrAt implements vfs.FilesystemImpl.SetXattrAt.
func (fs *filesystem) SetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetXattrOptions) error {
	// Verity file system is read-only.
	return linuxerr.EROFS
}

// RemoveXattrAt implements vfs.FilesystemImpl.RemoveXattrAt.
func (fs *filesystem) RemoveXattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	// Verity file system is read-only.
	return linuxerr.EROFS
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	fs.renameMu.RLock()
	defer fs.renameMu.RUnlock()
	mnt := vd.Mount()
	d := vd.Dentry().Impl().(*dentry)
	for {
		if mnt == vfsroot.Mount() && &d.vfsd == vfsroot.Dentry() {
			return vfs.PrependPathAtVFSRootError{}
		}
		if &d.vfsd == mnt.Root() {
			return nil
		}
		if d.parent == nil {
			return vfs.PrependPathAtNonMountRootError{}
		}
		b.PrependComponent(d.name)
		d = d.parent
	}
}
