// Copyright 2018 Google Inc.
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
)

func parseCachePolicy(policy string) (cachePolicy, error) {
	switch policy {
	case "fscache":
		return cacheAll, nil
	case "none":
		return cacheNone, nil
	case "fscache_writethrough":
		return cacheAllWritethrough, nil
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

// usePageCache determines whether the page cache should be used for the given
// inode.
func (cp cachePolicy) usePageCache(inode *fs.Inode) bool {
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

// revalidateDirent indicates that dirents should be revalidated after they are
// looked up.
func (cp cachePolicy) revalidateDirent() bool {
	return cp == cacheNone
}

// keepDirent indicates that dirents should be kept pinned in the dirent tree
// even if there are no application references on the file.
func (cp cachePolicy) keepDirent(inode *fs.Inode) bool {
	if cp == cacheNone {
		return false
	}
	sattr := inode.StableAttr
	// NOTE: Only cache files, directories, and symlinks.
	return fs.IsFile(sattr) || fs.IsDir(sattr) || fs.IsSymlink(sattr)
}

// cacheNegativeDirents indicates that negative dirents should be held in the
// dirent tree.
func (cp cachePolicy) cacheNegativeDirents() bool {
	return cp == cacheAll || cp == cacheAllWritethrough
}
