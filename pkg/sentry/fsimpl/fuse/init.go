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

	// The FUSE_INIT_IN flags sent to the daemon.
	// TODO(gvisor.dev/issue/3199): complete the flags.
	fuseDefaultInitFlags = linux.FUSE_MAX_PAGES
)

// Adjustable maximums for Connection's cogestion control parameters.
// Used as the upperbound of the config values.
// Currently we do not support adjustment to them.
var (
	MaxUserBackgroundRequest   uint16 = fuseDefaultMaxBackground
	MaxUserCongestionThreshold uint16 = fuseDefaultCongestionThreshold
)

// InitSend sends a FUSE_INIT request.
func (conn *connection) InitSend(creds *auth.Credentials, pid uint32) error {
	in := linux.FUSEInitIn{
		Major: linux.FUSE_KERNEL_VERSION,
		Minor: linux.FUSE_KERNEL_MINOR_VERSION,
		// TODO(gvisor.dev/issue/3196): find appropriate way to calculate this
		MaxReadahead: fuseDefaultMaxReadahead,
		Flags:        fuseDefaultInitFlags,
	}

	req, err := conn.NewRequest(creds, pid, 0, linux.FUSE_INIT, &in)
	if err != nil {
		return err
	}

	// Since there is no task to block on and FUSE_INIT is the request
	// to unblock other requests, use nil.
	return conn.CallAsync(nil, req)
}

// InitRecv receives a FUSE_INIT reply and process it.
func (conn *connection) InitRecv(res *Response, hasSysAdminCap bool) error {
	if err := res.Error(); err != nil {
		return err
	}

	var out linux.FUSEInitOut
	if err := res.UnmarshalPayload(&out); err != nil {
		return err
	}

	return conn.initProcessReply(&out, hasSysAdminCap)
}

// Process the FUSE_INIT reply from the FUSE server.
func (conn *connection) initProcessReply(out *linux.FUSEInitOut, hasSysAdminCap bool) error {
	// No support for old major fuse versions.
	if out.Major != linux.FUSE_KERNEL_VERSION {
		conn.connInitError = true

		// Set the connection as initialized and unblock the blocked requests
		// (i.e. return error for them).
		conn.SetInitialized()

		return nil
	}

	// Start processing the reply.
	conn.connInitSuccess = true
	conn.minor = out.Minor

	// No support for limits before minor version 13.
	if out.Minor >= 13 {
		conn.bgLock.Lock()

		if out.MaxBackground > 0 {
			conn.maxBackground = out.MaxBackground

			if !hasSysAdminCap &&
				conn.maxBackground > MaxUserBackgroundRequest {
				conn.maxBackground = MaxUserBackgroundRequest
			}
		}

		if out.CongestionThreshold > 0 {
			conn.congestionThreshold = out.CongestionThreshold

			if !hasSysAdminCap &&
				conn.congestionThreshold > MaxUserCongestionThreshold {
				conn.congestionThreshold = MaxUserCongestionThreshold
			}
		}

		conn.bgLock.Unlock()
	}

	// No support for the following flags before minor version 6.
	if out.Minor >= 6 {
		conn.asyncRead = out.Flags&linux.FUSE_ASYNC_READ != 0
		conn.bigWrites = out.Flags&linux.FUSE_BIG_WRITES != 0
		conn.dontMask = out.Flags&linux.FUSE_DONT_MASK != 0
		conn.writebackCache = out.Flags&linux.FUSE_WRITEBACK_CACHE != 0
		conn.cacheSymlinks = out.Flags&linux.FUSE_CACHE_SYMLINKS != 0
		conn.abortErr = out.Flags&linux.FUSE_ABORT_ERROR != 0

		// TODO(gvisor.dev/issue/3195): figure out how to use TimeGran (0 < TimeGran <= fuseMaxTimeGranNs).

		if out.Flags&linux.FUSE_MAX_PAGES != 0 {
			maxPages := out.MaxPages
			if maxPages < 1 {
				maxPages = 1
			}
			if maxPages > fuseMaxMaxPages {
				maxPages = fuseMaxMaxPages
			}
			conn.maxPages = maxPages
		}
	}

	// No support for negotiating MaxWrite before minor version 5.
	if out.Minor >= 5 {
		conn.maxWrite = out.MaxWrite
	} else {
		conn.maxWrite = fuseMinMaxWrite
	}
	if conn.maxWrite < fuseMinMaxWrite {
		conn.maxWrite = fuseMinMaxWrite
	}

	// Set connection as initialized and unblock the requests
	// issued before init.
	conn.SetInitialized()

	return nil
}
