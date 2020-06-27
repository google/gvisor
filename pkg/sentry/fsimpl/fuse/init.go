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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// consts used by FUSE_INIT negotiation.
const (
	// fuseMaxMaxPages is the maximum value for MaxPages received in InitOut.
	// Follow the same behavior as unix fuse implementation.
	fuseMaxMaxPages = 256

	// Maximum value for the time granularity for file time stamps, 1s.
	// Follow the same behavior as unix fuse implementation.
	fuseMaxTimeGranNs = 1000000000

	// Minimum value for MaxWrite.
	// Follow the same behavior as unix fuse implementation.
	fuseMinMaxWrite = 4096

	// Temporary default value for max readahead, 128kb.
	fuseDefaultMaxReadahead = 131072

	// The FUSE_INNT_IN flags sent to the daemon.
	// TODO(gvisor.dev/issue/3199): complete the flags.
	fuseDefaultInitFlags = linux.FUSE_MAX_PAGES
)

// Adjustable maximums for Connection's cogestion control parameters.
// Used as the upperbound of the config values.
// TODO(gvisor.dev/issue/3197): add adjust support (need to verify the new values are not zero).
var (
	MaxUserBackgroundRequest   uint16 = fuseDefaultMaxBackground
	MaxUserCongestionThreshold uint16 = fuseDefaultCongestionThreshold
)

// InitSend sends a FUSE_INIT request.
func (fs *filesystem) InitSend(creds *auth.Credentials, pid uint32) error {
	req, err := fs.initBuildRequest(creds, pid)
	if err != nil {
		return err
	}

	_, err = fs.conn.Call(nil, req)
	return err
}

// InitRecv receives a FUSE_INIT reply and process it.
func (fs *filesystem) InitRecv(creds *auth.Credentials, rootUserNs *auth.UserNamespace, res *Response) error {
	if err := res.Error(); err != nil {
		return err
	}

	var out linux.FUSEInitOut
	if err := res.UnmarshalPayload(&out); err != nil {
		return err
	}

	return fs.initProcessReply(creds, rootUserNs, &out)
}

// Builds a FUSE_INIT request.
func (fs *filesystem) initBuildRequest(creds *auth.Credentials, pid uint32) (*Request, error) {
	in := linux.FUSEInitIn{
		Major: linux.FUSE_KERNEL_VERSION,
		Minor: linux.FUSE_KERNEL_MINOR_VERSION,
		// TODO(gvisor.dev/issue/3196): find appropriate way to calculate this
		MaxReadahead: fuseDefaultMaxReadahead,
		Flags:        fuseDefaultInitFlags,
	}

	return fs.conn.NewRequest(creds, pid, 0, linux.FUSE_INIT, &in)
}

// Process the FUSE_INIT reply from the FUSE server.
func (fs *filesystem) initProcessReply(creds *auth.Credentials, rootUserNs *auth.UserNamespace, out *linux.FUSEInitOut) error {
	// No support for old major fuse versions.
	// This behavior is consistent with the Linux kernel (v5.8).
	if out.Major != linux.FUSE_KERNEL_VERSION {
		fs.conn.ConnInitError = true
	} else {
		fs.conn.ConnInitSuccess = true
		fs.conn.Minor = out.Minor

		// No support for limits before minor version 13.
		if out.Minor >= 13 {
			isCapable := creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, rootUserNs)

			fs.conn.BgLock.Lock()

			if out.MaxBackground > 0 {
				fs.conn.MaxBackground = out.MaxBackground

				if !isCapable &&
					fs.conn.MaxBackground > MaxUserBackgroundRequest {
					fs.conn.MaxBackground = MaxUserBackgroundRequest
				}
			}

			if out.CongestionThreshold > 0 {
				fs.conn.CongestionThreshold = out.CongestionThreshold

				if !isCapable &&
					fs.conn.CongestionThreshold > MaxUserCongestionThreshold {
					fs.conn.CongestionThreshold = MaxUserCongestionThreshold
				}
			}

			fs.conn.BgLock.Unlock()
		}

		// No support for the following flags before minor version 6.
		if out.Minor >= 6 {
			if out.Flags&linux.FUSE_ASYNC_READ != 0 {
				fs.conn.AsyncRead = true
			}

			if out.Flags&linux.FUSE_POSIX_LOCKS == 0 {
				fs.conn.NoLock = true
			}

			// No support for FLOCK flag before minor version 17.
			if out.Minor >= 17 {
				if out.Flags&linux.FUSE_FLOCK_LOCKS == 0 {
					fs.conn.NoFLock = true
				}
			} else {
				if out.Flags&linux.FUSE_POSIX_LOCKS == 0 {
					fs.conn.NoFLock = true
				}
			}

			if out.Flags&linux.FUSE_ATOMIC_O_TRUNC != 0 {
				fs.conn.AtomicOTrunc = true
			}

			// No support for EXPORT flag before minor version 9.
			if out.Minor >= 9 {
				if out.Flags&linux.FUSE_EXPORT_SUPPORT != 0 {
					fs.conn.ExportSupport = true
				}
			}

			if out.Flags&linux.FUSE_BIG_WRITES != 0 {
				fs.conn.BigWrites = true
			}

			if out.Flags&linux.FUSE_DONT_MASK != 0 {
				fs.conn.DontMask = true
			}

			if out.Flags&linux.FUSE_AUTO_INVAL_DATA != 0 {
				fs.conn.AutoInvalData = true
			} else if out.Flags&linux.FUSE_EXPLICIT_INVAL_DATA != 0 {
				fs.conn.ExplicitInvalData = true
			}

			if out.Flags&linux.FUSE_DO_READDIRPLUS != 0 {
				fs.conn.DoReaddirplus = true
				if out.Flags&linux.FUSE_READDIRPLUS_AUTO != 0 {
					fs.conn.ReaddirplusAuto = true
				}
			}

			if out.Flags&linux.FUSE_ASYNC_DIO != 0 {
				fs.conn.AsyncDio = true
			}

			if out.Flags&linux.FUSE_WRITEBACK_CACHE != 0 {
				fs.conn.WritebackCache = true
			}

			if out.Flags&linux.FUSE_PARALLEL_DIROPS != 0 {
				fs.conn.ParallelDirops = true
			}

			if out.Flags&linux.FUSE_HANDLE_KILLPRIV != 0 {
				fs.conn.HandleKillpriv = true
			}

			// if out.TimeGran > 0 && out.TimeGran <= fuseMaxTimeGranNs {
			// TODO(gvisor.dev/issue/3195): figure out how to use this.
			// superBlock.s_time_gran = reply.TimeGran
			// }

			if out.Flags&linux.FUSE_POSIX_ACL != 0 {
				fs.conn.DefaultPermissions = true
				fs.conn.PosixACL = true
				// TODO(gvisor.dev/issue/3194): add xattr handler support.
				// superBlock.xattrHandler =
			}

			if out.Flags&linux.FUSE_CACHE_SYMLINKS != 0 {
				fs.conn.CacheSymlinks = true
			}

			if out.Flags&linux.FUSE_ABORT_ERROR != 0 {
				fs.conn.AbortErr = true
			}

			if out.Flags&linux.FUSE_MAX_PAGES != 0 {
				maxPages := out.MaxPages
				if maxPages < 1 {
					maxPages = 1
				}
				if maxPages > fuseMaxMaxPages {
					maxPages = fuseMaxMaxPages
				}
				fs.conn.MaxPages = maxPages
			}
		} else {
			fs.conn.NoLock = true
			fs.conn.NoFLock = true
		}

		// No support for negotiating MaxWrite before minor version 5.
		if out.Minor < 5 {
			fs.conn.MaxWrite = fuseMinMaxWrite
		} else {
			fs.conn.MaxWrite = out.MaxWrite
		}
		if fs.conn.MaxWrite < fuseMinMaxWrite {
			fs.conn.MaxWrite = fuseMinMaxWrite
		}
	}

	fs.conn.SetInitialized()

	// TODO(gvisor.dev/issue/3185): unblock all blocked requests so far.
	// close(fs.conn.blockedWaitQueueCh)

	return nil
}
