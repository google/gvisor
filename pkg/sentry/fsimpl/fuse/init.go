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

package fuse

import (
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

const (
	// FUSE_MAX_TIME_GRAN_NS is the max value for the time granularity for file time stamps, 1s.
	FUSE_MAX_TIME_GRAN_NS = 1000000000 
)

// Init sends a FUSE_INIT request, waits for the reply, and processes it.
func (fs *filesystem) Init(creds *auth.Credentials, k *kernel.Kernel, pid uint32) error {
	req, err := fs.initBuildRequest(creds, pid)
	if err != nil {
		return err
	}

	res, err := fs.fuseConn.CallTaskNonBlock(req)
	if err != nil {
		return err
	}
	if err := res.Error(); err != nil {
		return err
	}

	var out linux.FUSEInitOut
	if err := res.UnmarshalPayload(&out); err != nil {
		return err
	}

	return fs.initProcessReply(k, creds, &out)
}

// initBuildRequest analogous to fuse_send_init() in fs/fuse/inode.c
func (fs *filesystem) initBuildRequest(creds *auth.Credentials, pid uint32) (*Request, error) {
	in := linux.FUSEInitIn{
		Major: linux.FUSE_KERNEL_VERSION,
		Minor: linux.FUSE_KERNEL_MINOR_VERSION,
		// TODO: find appropriate way to calculate this
		MaxReadahead: linux.FUSE_MAX_READAHREAD_DEFAULT, 
		Flags: linux.FUSE_ASYNC_READ |
			linux.FUSE_POSIX_LOCKS |
			linux.FUSE_ATOMIC_O_TRUNC |
			linux.FUSE_EXPORT_SUPPORT |
			linux.FUSE_BIG_WRITES |
			linux.FUSE_DONT_MASK |
			linux.FUSE_SPLICE_WRITE |
			linux.FUSE_SPLICE_MOVE |
			linux.FUSE_SPLICE_READ |
			linux.FUSE_FLOCK_LOCKS |
			linux.FUSE_HAS_IOCTL_DIR |
			linux.FUSE_AUTO_INVAL_DATA |
			linux.FUSE_DO_READDIRPLUS |
			linux.FUSE_READDIRPLUS_AUTO |
			linux.FUSE_ASYNC_DIO |
			linux.FUSE_WRITEBACK_CACHE |
			linux.FUSE_NO_OPEN_SUPPORT |
			linux.FUSE_PARALLEL_DIROPS |
			linux.FUSE_HANDLE_KILLPRIV |
			linux.FUSE_POSIX_ACL |
			linux.FUSE_ABORT_ERROR |
			linux.FUSE_MAX_PAGES |
			linux.FUSE_CACHE_SYMLINKS |
			linux.FUSE_NO_OPENDIR_SUPPORT |
			linux.FUSE_EXPLICIT_INVAL_DATA,
	}

	return fs.fuseConn.NewRequest(creds, pid, 0, linux.FUSE_INIT, &in)
}

// initProcessReply analogous to process_init_reply() in fs/fuse/inode.c
func (fs *filesystem) initProcessReply(k *kernel.Kernel, creds *auth.Credentials, out *linux.FUSEInitOut) error {
	// No support for old major fuse versions.
	// This behaves the same as the Linux kernel (currently v5.8).
	if out.Major != linux.FUSE_KERNEL_VERSION {
		fs.fuseConn.ConnError = true
	} else {
		// TODO: figure out how to use ra_pages
		// var ra_pages uint32

		fs.initProcessLimits(k, creds, out)

		// No support for the following flags before minor version 6.
		if out.Minor >= 6 {
			// ra_pages = reply.max_readahead / PAGE_SIZE
			if out.Flags&linux.FUSE_ASYNC_READ == linux.FUSE_ASYNC_READ {
				fs.fuseConn.AsyncRead = true
			}

			if !(out.Flags&linux.FUSE_POSIX_LOCKS == linux.FUSE_POSIX_LOCKS) {
				fs.fuseConn.NoLock = true
			}

			// No support for FLOCK flag before minor version 17.
			if out.Minor >= 17 {
				if !(out.Flags & linux.FUSE_FLOCK_LOCKS == linux.FUSE_FLOCK_LOCKS) {
					fs.fuseConn.NoFLock = true
				}
			} else {
				if !(out.Flags & linux.FUSE_POSIX_LOCKS == linux.FUSE_POSIX_LOCKS) {
					fs.fuseConn.NoFLock = true
				}
			}

			if out.Flags & linux.FUSE_ATOMIC_O_TRUNC == linux.FUSE_ATOMIC_O_TRUNC {
				fs.fuseConn.AtomicOTrunc = true
			}

			// No support for EXPORT flag before minor version 9.
			if out.Minor >= 9 {
				if out.Flags & linux.FUSE_EXPORT_SUPPORT == linux.FUSE_EXPORT_SUPPORT {
					fs.fuseConn.ExportSupport = true
				}
			}

			if out.Flags & linux.FUSE_BIG_WRITES == linux.FUSE_BIG_WRITES {
				fs.fuseConn.BigWrites = true
			}

			if out.Flags & linux.FUSE_DONT_MASK == linux.FUSE_DONT_MASK {
				fs.fuseConn.DontMask = true
			}

			if out.Flags & linux.FUSE_AUTO_INVAL_DATA == linux.FUSE_AUTO_INVAL_DATA {
				fs.fuseConn.AutoInvalData = true
			} else if out.Flags & linux.FUSE_EXPLICIT_INVAL_DATA == linux.FUSE_EXPLICIT_INVAL_DATA {
				fs.fuseConn.ExplicitInvalData = true
			}

			if out.Flags & linux.FUSE_DO_READDIRPLUS == linux.FUSE_DO_READDIRPLUS {
				fs.fuseConn.DoReaddirplus = true
				if out.Flags & linux.FUSE_READDIRPLUS_AUTO == linux.FUSE_READDIRPLUS_AUTO {
					fs.fuseConn.ReaddirplusAuto = true
				}
			}

			if out.Flags & linux.FUSE_ASYNC_DIO == linux.FUSE_ASYNC_DIO {
				fs.fuseConn.AsyncDio = true
			}

			if out.Flags & linux.FUSE_WRITEBACK_CACHE == linux.FUSE_WRITEBACK_CACHE {
				fs.fuseConn.WritebackCache = true
			}

			if out.Flags & linux.FUSE_PARALLEL_DIROPS == linux.FUSE_PARALLEL_DIROPS {
				fs.fuseConn.ParallelDirops = true
			}

			if out.Flags & linux.FUSE_HANDLE_KILLPRIV == linux.FUSE_HANDLE_KILLPRIV {
				fs.fuseConn.HandleKillpriv = true
			}

			if out.TimeGran > 0 && out.TimeGran <= FUSE_MAX_TIME_GRAN_NS {
				// TODO: figure out how to use this
				// superBlock.s_time_gran = reply.TimeGran
			}

			if out.Flags & linux.FUSE_POSIX_ACL == linux.FUSE_POSIX_ACL {
				fs.fuseConn.DefaultPermissions = true
				fs.fuseConn.PosixAcl = true
				// TODO: add xattr handler support
				// superBlock.s_xattr = fuse_acl_xattr_handlers
			}

			if out.Flags & linux.FUSE_CACHE_SYMLINKS == linux.FUSE_CACHE_SYMLINKS {
				fs.fuseConn.CacheSymlinks = true
			}

			if out.Flags & linux.FUSE_ABORT_ERROR == linux.FUSE_ABORT_ERROR {
				fs.fuseConn.AbortErr = true
			}

			if out.Flags & linux.FUSE_MAX_PAGES == linux.FUSE_MAX_PAGES {
				maxPages := out.MaxPages
				if maxPages < 1 {
					maxPages = 1
				}
				if maxPages > linux.FUSE_MAX_MAX_PAGES {
					maxPages = linux.FUSE_MAX_MAX_PAGES
				}
				fs.fuseConn.MaxPages = maxPages
			}
		} else {
			// raPages = fc->max_read / PAGE_SIZE
			fs.fuseConn.NoLock = true
			fs.fuseConn.NoFLock = true
		}

		// fc->sb->s_bdi->ra_pages =
		// 		min(fc->sb->s_bdi->ra_pages, ra_pages)
		fs.fuseConn.Minor = out.Minor

		// No support for max_write before minor version 5.
		if out.Minor < 5 {
			fs.fuseConn.MaxWrite = linux.FUSE_MIN_MAX_WRITE
		} else {
			fs.fuseConn.MaxWrite = out.MaxWrite
		}
		if out.MaxWrite < linux.FUSE_MIN_MAX_WRITE {
			fs.fuseConn.MaxWrite = linux.FUSE_MIN_MAX_WRITE
		}

		fs.fuseConn.ConnInit = true
	}

	fs.fuseConn.setInitialized()

	// TODO: unblock all blocked requests so far
	// wake_up_all(fs.fussConn.blockedWaitq)

	return nil
}

// initProcessLimits analogous to process_init_limits()
func (fs *filesystem) initProcessLimits(k *kernel.Kernel, creds *auth.Credentials, out *linux.FUSEInitOut) {
	// No support for minor version before 13.
	if out.Minor < 13 {
		return
	}

	isCapable := creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, k.RootUserNamespace())

	totalSize := k.MemoryFile().TotalSize()
	sanitizeFuseBgLimit(totalSize, &MaxUserBackgroundRequest)
	sanitizeFuseBgLimit(totalSize, &MaxUserCongestionThreshold)

	fs.fuseConn.BgLock.Lock()
	defer fs.fuseConn.BgLock.Unlock()

	if out.MaxBackground > 0 {
		fs.fuseConn.MaxBackground = out.MaxBackground

		if !isCapable &&
			fs.fuseConn.MaxBackground > MaxUserBackgroundRequest {
			fs.fuseConn.MaxBackground = MaxUserBackgroundRequest
		}
	}
	if out.CongestionThreshold > 0 {
		fs.fuseConn.CongestionThreshold = out.CongestionThreshold

		if !isCapable &&
			fs.fuseConn.CongestionThreshold > MaxUserCongestionThreshold {
			fs.fuseConn.CongestionThreshold = MaxUserCongestionThreshold
		}
	}
}

// analogous to sanitize_global_limit() from inode.c 
func sanitizeFuseBgLimit(totalSize uint64, limit *uint16) {
	// Assume request has 392 bytes
	const requsetSize = 392
	// Magic number from unix code
	const memoryFraction = 13

	// Calculate default number of async request
	// to be 1/2^13 of total memory
	if *limit == 0 {
		newLimit := (totalSize >> memoryFraction) / requsetSize
		if newLimit > math.MaxUint16 {
			newLimit = math.MaxUint16
		}
		*limit = uint16(newLimit)
	}
}