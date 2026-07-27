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

package kernel

import (
	"crypto/sha1"
	"crypto/sha256"
	"hash"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// resolveBinaryHashes returns the requested binary digests (SHA-256 and/or SHA-1)
// inside seccheck.ExecveHashes for the given executable. Enabled algorithms are
// derived from cache.Opts(). If cache is nil, caching is unregistered and empty
// digests are returned immediately. Otherwise, it returns cached digests when
// available or computes missing digests in a single PRead pass.
func resolveBinaryHashes(t *Task, executable *vfs.FileDescription, cache *seccheck.ExecveHashCache) seccheck.ExecveHashes {
	if executable == nil || cache == nil {
		return seccheck.ExecveHashes{}
	}
	opts := cache.Opts()
	statOpts := vfs.StatOptions{
		Mask: linux.STATX_TYPE | linux.STATX_INO | linux.STATX_SIZE | linux.STATX_MTIME,
	}
	stat, err := executable.Stat(t, statOpts)

	// Only compute and cache digests if the executable is explicitly reported as a regular
	// file. This prevents attempts to read and hash special files (e.g. char/block devices,
	// FIFOs, directories).
	if err != nil || stat.Mask&linux.STATX_TYPE == 0 || stat.Mode&linux.S_IFMT != linux.S_IFREG {
		return seccheck.ExecveHashes{}
	}

	// Use the LRU cache only when the filesystem provides all required attributes
	// (inode, size, and mtime).
	if cache.Capacity() > 0 && stat.Mask&(linux.STATX_INO|linux.STATX_SIZE|linux.STATX_MTIME) == (linux.STATX_INO|linux.STATX_SIZE|linux.STATX_MTIME) {
		mountID := uint64(0)
		if mnt := executable.Mount(); mnt != nil {
			mountID = mnt.ID
		}
		key := seccheck.ExecveKey{
			MountID:   mountID,
			Ino:       stat.Ino,
			Size:      stat.Size,
			MtimeSec:  stat.Mtime.Sec,
			MtimeNsec: stat.Mtime.Nsec,
		}
		hit, ok := cache.Lookup(key)
		got256 := hit.SHA256
		got1 := hit.SHA1

		compute256 := opts.SHA256 && len(got256) == 0
		compute1 := opts.SHA1 && len(got1) == 0

		if !compute256 && !compute1 && ok {
			return seccheck.ExecveHashes{SHA256: got256, SHA1: got1}
		}

		if compute256 || compute1 {
			newHashes := computeBinaryHashes(t, executable, seccheck.ExecveHashOptions{SHA256: compute256, SHA1: compute1})
			if compute256 && newHashes.SHA256 != nil {
				got256 = newHashes.SHA256
			}
			if compute1 && newHashes.SHA1 != nil {
				got1 = newHashes.SHA1
			}
			if len(got256) > 0 || len(got1) > 0 {
				cache.Add(key, seccheck.ExecveHashes{
					SHA256: got256,
					SHA1:   got1,
				})
			}
		}
		return seccheck.ExecveHashes{SHA256: got256, SHA1: got1}
	}
	// Fall back to computing digests directly without using or updating the cache.
	return computeBinaryHashes(t, executable, opts)
}

// computeBinaryHashes reads executable in 1MB chunks and computes requested
// SHA-256/SHA-1 digests in a single pass, returning them in seccheck.ExecveHashes.
func computeBinaryHashes(ctx context.Context, executable *vfs.FileDescription, opts seccheck.ExecveHashOptions) seccheck.ExecveHashes {
	var h256, h1 hash.Hash
	if opts.SHA256 {
		h256 = sha256.New()
	}
	if opts.SHA1 {
		h1 = sha1.New()
	}

	buf := make([]byte, 1024*1024) // Read 1MB at a time.
	dest := usermem.BytesIOSequence(buf)
	offset := int64(0)

	for {
		if read, err := executable.PRead(ctx, dest, offset, vfs.ReadOptions{}); err == nil {
			if h256 != nil {
				h256.Write(buf[0:read])
			}
			if h1 != nil {
				h1.Write(buf[0:read])
			}
			offset += read

		} else if err == io.EOF {
			if read > 0 {
				if h256 != nil {
					h256.Write(buf[0:read])
				}
				if h1 != nil {
					h1.Write(buf[0:read])
				}
			}
			var res256, res1 []byte
			if h256 != nil {
				res256 = h256.Sum(nil)
			}
			if h1 != nil {
				res1 = h1.Sum(nil)
			}
			return seccheck.ExecveHashes{SHA256: res256, SHA1: res1}

		} else {
			log.Warningf("Failed to read executable for binary hash computation: %v", err)
			return seccheck.ExecveHashes{}
		}
	}
}
