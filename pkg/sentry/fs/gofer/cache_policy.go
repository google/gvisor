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

package gofer

import (
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
)

// cachePolicy is a 9p cache policy. It has methods that determine what to
// cache (if anything) for a given inode.
type cachePolicy int

const (
	// Cache nothing.
	cacheNone cachePolicy = iota

	// Use virtual file system cache for everything.
	cacheAll

	// Use virtual file system cache for everything, but send writes to the
	// fs agent immediately.
	cacheAllWritethrough

	// Use the (host) page cache for reads/writes, but don't cache anything
	// else. This allows the sandbox filesystem to stay in sync with any
	// changes to the remote filesystem.
	//
	// This policy should *only* be used with remote filesystems that
	// donate their host FDs to the sandbox and thus use the host page
	// cache, otherwise the dirent state will be inconsistent.
	cacheRemoteRevalidating
)

// String returns the string name of the cache policy.
func (cp cachePolicy) String() string {
	switch cp {
	case cacheNone:
		return "cacheNone"
	case cacheAll:
		return "cacheAll"
	case cacheAllWritethrough:
		return "cacheAllWritethrough"
	case cacheRemoteRevalidating:
		return "cacheRemoteRevalidating"
	default:
		return "unknown"
	}
}

func parseCachePolicy(policy string) (cachePolicy, error) {
	switch policy {
	case "fscache":
		return cacheAll, nil
	case "none":
		return cacheNone, nil
	case "fscache_writethrough":
		return cacheAllWritethrough, nil
	case "remote_revalidating":
		return cacheRemoteRevalidating, nil
	}
	return cacheNone, fmt.Errorf("unsupported cache mode: %s", policy)
}

// cacheUAtters determines whether unstable attributes should be cached for the
// given inode.
func (cp cachePolicy) cacheUAttrs(inode *fs.Inode) bool {
	if !fs.IsFile(inode.StableAttr) && !fs.IsDir(inode.StableAttr) {
		return false
	}
	return cp == cacheAll || cp == cacheAllWritethrough
}

// cacheReaddir determines whether readdir results should be cached.
func (cp cachePolicy) cacheReaddir() bool {
	return cp == cacheAll || cp == cacheAllWritethrough
}

// useCachingInodeOps determines whether the page cache should be used for the
// given inode. If the remote filesystem donates host FDs to the sentry, then
// the host kernel's page cache will be used, otherwise we will use a
// sentry-internal page cache.
func (cp cachePolicy) useCachingInodeOps(inode *fs.Inode) bool {
	// Do cached IO for regular files only. Some "character devices" expect
	// no caching.
	if !fs.IsFile(inode.StableAttr) {
		return false
	}
	return cp == cacheAll || cp == cacheAllWritethrough
}

// writeThough indicates whether writes to the file should be synced to the
// gofer immediately.
func (cp cachePolicy) writeThrough(inode *fs.Inode) bool {
	return cp == cacheNone || cp == cacheAllWritethrough
}

// revalidate revalidates the child Inode if the cache policy allows it.
//
// Depending on the cache policy, revalidate will walk from the parent to the
// child inode, and if any unstable attributes have changed, will update the
// cached attributes on the child inode. If the walk fails, or the returned
// inode id is different from the one being revalidated, then the entire Dirent
// must be reloaded.
func (cp cachePolicy) revalidate(ctx context.Context, name string, parent, child *fs.Inode) bool {
	if cp == cacheAll || cp == cacheAllWritethrough {
		return false
	}

	if cp == cacheNone {
		return true
	}

	childIops, ok := child.InodeOperations.(*inodeOperations)
	if !ok {
		panic(fmt.Sprintf("revalidating inode operations of unknown type %T", child.InodeOperations))
	}
	parentIops, ok := parent.InodeOperations.(*inodeOperations)
	if !ok {
		panic(fmt.Sprintf("revalidating inode operations with parent of unknown type %T", parent.InodeOperations))
	}

	// Walk from parent to child again.
	//
	// TODO(b/112031682): If we have a directory FD in the parent
	// inodeOperations, then we can use fstatat(2) to get the inode
	// attributes instead of making this RPC.
	qids, _, mask, attr, err := parentIops.fileState.file.walkGetAttr(ctx, []string{name})
	if err != nil {
		// Can't look up the name. Trigger reload.
		return true
	}

	// If the Path has changed, then we are not looking at the file file.
	// We must reload.
	if qids[0].Path != childIops.fileState.key.Inode {
		return true
	}

	// If we are not caching unstable attrs, then there is nothing to
	// update on this inode.
	if !cp.cacheUAttrs(child) {
		return false
	}

	// Update the inode's cached unstable attrs.
	s := childIops.session()
	childIops.cachingInodeOps.UpdateUnstable(unstable(ctx, mask, attr, s.mounter, s.client))

	return false
}

// keep indicates that dirents should be kept pinned in the dirent tree even if
// there are no application references on the file.
func (cp cachePolicy) keep(d *fs.Dirent) bool {
	if cp == cacheNone {
		return false
	}
	sattr := d.Inode.StableAttr
	// NOTE(b/31979197): Only cache files, directories, and symlinks.
	return fs.IsFile(sattr) || fs.IsDir(sattr) || fs.IsSymlink(sattr)
}

// cacheNegativeDirents indicates that negative dirents should be held in the
// dirent tree.
func (cp cachePolicy) cacheNegativeDirents() bool {
	return cp == cacheAll || cp == cacheAllWritethrough
}
