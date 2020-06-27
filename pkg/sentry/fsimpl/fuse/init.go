// Copyright 2019 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

const (
	// FUSE_DEFAULT_MAX_BACKGROUND is the maximum number of outstanding background requests.
	FUSE_DEFAULT_MAX_BACKGROUND = 12

	// FUSE_DEFAULT_CONGESTION_THRESHOLD is 75% of default maximum.
	FUSE_DEFAULT_CONGESTION_THRESHOLD = (FUSE_DEFAULT_MAX_BACKGROUND * 3 / 4)

	// FUSE_DEFAULT_MAX_PAGES_PER_REQ is the maximum number of pages that can be used in a single read request.
	FUSE_DEFAULT_MAX_PAGES_PER_REQ = 32
)

// Adjustable maximums for Connection's cogestion control
// TODO: add adjust support
var (
	MaxUserBackgroundRequest uint16 = FUSE_DEFAULT_MAX_BACKGROUND
	MaxUserCongestionThreshold uint16 = FUSE_DEFAULT_CONGESTION_THRESHOLD
)

// Init sends a FUSE_INIT request, waits for the reply, and handles it
// TODO: find proper way to handle the error
func (fs *filesystem) Init(ctx context.Context, creds *auth.Credentials) error {
	t := kernel.TaskFromContext(ctx)

	req, err := fs.initBuildRequest(t, creds)
	if err != nil {
		// local error in creating a request
		return err
	}

	res, err := fs.fuseConn.Call(t, req)
	if err != nil {
		// error in communication
		return err
	}
	if err := res.Error(); err != nil {
		return err
	}

	var reply linux.FUSEInitOut
	if err := res.UnmarshalPayload(&reply); err != nil {
		return err
	}

	if err := fs.initProcessReply(t, creds, &reply); err != nil {
		// local error in processing reply
		return err
	}

	return nil
}

// initBuildRequest analogous to fuse_send_init() in fs/fuse/inode.c
func (fs *filesystem) initBuildRequest(t *kernel.Task, creds *auth.Credentials) (*Request, error) {
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

	return fs.fuseConn.NewRequest(creds, uint32(t.ThreadID()), 0, linux.FUSE_INIT, &in)
}

// initProcessReply analogous to process_init_reply() in fs/fuse/inode.c
func (fs *filesystem) initProcessReply(t *kernel.Task, creds *auth.Credentials, reply *linux.FUSEInitOut) error {
	// TODO: figure out better way to handle magic const version numbers from inode.c

	if reply.Major != linux.FUSE_KERNEL_VERSION {
		fs.fuseConn.ConnError = true
	} else {
		// TODO: figure out how to use ra_pages
		// var ra_pages uint32

		fs.initProcessLimits(t, creds, reply)

		const minMinorVersionFlag = 6
		if reply.Minor >= minMinorVersionFlag {
			// ra_pages = reply.max_readahead / PAGE_SIZE
			if reply.Flags&linux.FUSE_ASYNC_READ == linux.FUSE_ASYNC_READ {
				fs.fuseConn.AsyncRead = true
			}

			if !(reply.Flags&linux.FUSE_POSIX_LOCKS == linux.FUSE_POSIX_LOCKS) {
				fs.fuseConn.NoLock = true
			}

			const minMinorVersionFlock = 17
			if reply.Minor >= minMinorVersionFlock {
				if !(reply.Flags & linux.FUSE_FLOCK_LOCKS == linux.FUSE_FLOCK_LOCKS) {
					fs.fuseConn.NoFLock = true
				}
			} else {
				if !(reply.Flags & linux.FUSE_POSIX_LOCKS == linux.FUSE_POSIX_LOCKS) {
					fs.fuseConn.NoFLock = true
				}
			}

			if reply.Flags & linux.FUSE_ATOMIC_O_TRUNC == linux.FUSE_ATOMIC_O_TRUNC {
				fs.fuseConn.AtomicOTrunc = true
			}

			const minMinorVersionExportSupport = 9
			if reply.Minor >= minMinorVersionExportSupport {
				if reply.Flags & linux.FUSE_EXPORT_SUPPORT == linux.FUSE_EXPORT_SUPPORT {
					fs.fuseConn.ExportSupport = true
				}
			}

			if reply.Flags & linux.FUSE_BIG_WRITES == linux.FUSE_BIG_WRITES {
				fs.fuseConn.BigWrites = true
			}

			if reply.Flags & linux.FUSE_DONT_MASK == linux.FUSE_DONT_MASK {
				fs.fuseConn.DontMask = true
			}

			if reply.Flags & linux.FUSE_AUTO_INVAL_DATA == linux.FUSE_AUTO_INVAL_DATA {
				fs.fuseConn.AutoInvalData = true
			} else if reply.Flags & linux.FUSE_EXPLICIT_INVAL_DATA == linux.FUSE_EXPLICIT_INVAL_DATA {
				fs.fuseConn.ExplicitInvalData = true
			}

			if reply.Flags & linux.FUSE_DO_READDIRPLUS == linux.FUSE_DO_READDIRPLUS {
				fs.fuseConn.DoReaddirplus = true
				if reply.Flags & linux.FUSE_READDIRPLUS_AUTO == linux.FUSE_READDIRPLUS_AUTO {
					fs.fuseConn.ReaddirplusAuto = true
				}
			}

			if reply.Flags & linux.FUSE_ASYNC_DIO == linux.FUSE_ASYNC_DIO {
				fs.fuseConn.AsyncDio = true
			}

			if reply.Flags & linux.FUSE_WRITEBACK_CACHE == linux.FUSE_WRITEBACK_CACHE {
				fs.fuseConn.WritebackCache = true
			}

			if reply.Flags & linux.FUSE_PARALLEL_DIROPS == linux.FUSE_PARALLEL_DIROPS {
				fs.fuseConn.ParallelDirops = true
			}

			if reply.Flags & linux.FUSE_HANDLE_KILLPRIV == linux.FUSE_HANDLE_KILLPRIV {
				fs.fuseConn.HandleKillpriv = true
			}

			const maxTimeGranNs = 1000000000
			if reply.TimeGran > 0 && reply.TimeGran <= maxTimeGranNs {
				// superBlock.s_time_gran = reply.TimeGran
			}

			if reply.Flags & linux.FUSE_POSIX_ACL == linux.FUSE_POSIX_ACL {
				fs.fuseConn.DefaultPermissions = true
				fs.fuseConn.PosixAcl = true
				// TODO: add xattr handler support
				// superBlock.s_xattr = fuse_acl_xattr_handlers
			}

			if reply.Flags & linux.FUSE_CACHE_SYMLINKS == linux.FUSE_CACHE_SYMLINKS {
				fs.fuseConn.CacheSymlinks = true
			}

			if reply.Flags & linux.FUSE_ABORT_ERROR == linux.FUSE_ABORT_ERROR {
				fs.fuseConn.AbortErr = true
			}

			if reply.Flags & linux.FUSE_MAX_PAGES == linux.FUSE_MAX_PAGES {
				maxPages := reply.MaxPages
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
		fs.fuseConn.Minor = reply.Minor

		const minMinorVersionMaxWrite = 5
		if reply.Minor < minMinorVersionMaxWrite {
			fs.fuseConn.MaxWrite = linux.FUSE_MIN_MAX_WRITE
		} else {
			fs.fuseConn.MaxWrite = reply.MaxWrite
		}
		if reply.MaxWrite < linux.FUSE_MIN_MAX_WRITE {
			fs.fuseConn.MaxWrite = linux.FUSE_MIN_MAX_WRITE
		}

		fs.fuseConn.ConnInit = true
	}

	// TODO: how to make sure other CPUs have seen this
	//smp_wmb()
	fs.fuseConn.Initialized = true

	// TODO: unblock all blocked requests so far
	// wake_up_all(fs.fussConn.blockedWaitq)

	return nil
}

// initProcessLimits analogous to process_init_limits()
func (fs *filesystem) initProcessLimits(t *kernel.Task, creds *auth.Credentials, reply *linux.FUSEInitOut) {
	const minMinorVersionLimits = 13
	if reply.Minor < minMinorVersionLimits {
		return
	}

	k := t.Kernel()

	isCapable := creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, k.RootUserNamespace())

	totalSize := k.MemoryFile().TotalSize()
	sanitizeFuseBgLimit(totalSize, &MaxUserBackgroundRequest)
	sanitizeFuseBgLimit(totalSize, &MaxUserCongestionThreshold)

	fs.fuseConn.BgLock.Lock()
	defer fs.fuseConn.BgLock.Unlock()

	if reply.MaxBackground > 0 {
		fs.fuseConn.MaxBackground = reply.MaxBackground

		if !isCapable &&
			fs.fuseConn.MaxBackground > MaxUserBackgroundRequest {
			fs.fuseConn.MaxBackground = MaxUserBackgroundRequest
		}
	}
	if reply.CongestionThreshold > 0 {
		fs.fuseConn.CongestionThreshold = reply.CongestionThreshold

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