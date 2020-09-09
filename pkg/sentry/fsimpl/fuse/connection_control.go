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
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
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

	// Minimum value for MaxWrite and MaxRead.
	// Follow the same behavior as unix fuse implementation.
	fuseMinMaxWrite = 4096
	fuseMinMaxRead  = 4096

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

// SetInitialized atomically sets the connection as initialized.
func (conn *connection) SetInitialized() {
	// Unblock the requests sent before INIT.
	close(conn.initializedChan)

	// Close the channel first to avoid the non-atomic situation
	// where conn.initialized is true but there are
	// tasks being blocked on the channel.
	// And it prevents the newer tasks from gaining
	// unnecessary higher chance to be issued before the blocked one.

	atomic.StoreInt32(&(conn.initialized), int32(1))
}

// IsInitialized atomically check if the connection is initialized.
// pairs with SetInitialized().
func (conn *connection) Initialized() bool {
	return atomic.LoadInt32(&(conn.initialized)) != 0
}

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

	initRes := fuseInitRes{initLen: res.DataLen()}
	if err := res.UnmarshalPayload(&initRes); err != nil {
		return err
	}

	return conn.initProcessReply(&initRes.initOut, hasSysAdminCap)
}

// Process the FUSE_INIT reply from the FUSE server.
// It tries to acquire the conn.asyncMu lock if minor version is newer than 13.
func (conn *connection) initProcessReply(out *linux.FUSEInitOut, hasSysAdminCap bool) error {
	// No matter error or not, always set initialzied.
	// to unblock the blocked requests.
	defer conn.SetInitialized()

	// No support for old major fuse versions.
	if out.Major != linux.FUSE_KERNEL_VERSION {
		conn.connInitError = true
		return nil
	}

	// Start processing the reply.
	conn.connInitSuccess = true
	conn.minor = out.Minor

	// No support for negotiating MaxWrite before minor version 5.
	if out.Minor >= 5 {
		conn.maxWrite = out.MaxWrite
	} else {
		conn.maxWrite = fuseMinMaxWrite
	}
	if conn.maxWrite < fuseMinMaxWrite {
		conn.maxWrite = fuseMinMaxWrite
	}

	// No support for the following flags before minor version 6.
	if out.Minor >= 6 {
		conn.asyncRead = out.Flags&linux.FUSE_ASYNC_READ != 0
		conn.bigWrites = out.Flags&linux.FUSE_BIG_WRITES != 0
		conn.dontMask = out.Flags&linux.FUSE_DONT_MASK != 0
		conn.writebackCache = out.Flags&linux.FUSE_WRITEBACK_CACHE != 0

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

	// No support for limits before minor version 13.
	if out.Minor >= 13 {
		conn.asyncMu.Lock()

		if out.MaxBackground > 0 {
			conn.asyncNumMax = out.MaxBackground

			if !hasSysAdminCap &&
				conn.asyncNumMax > MaxUserBackgroundRequest {
				conn.asyncNumMax = MaxUserBackgroundRequest
			}
		}

		if out.CongestionThreshold > 0 {
			conn.asyncCongestionThreshold = out.CongestionThreshold

			if !hasSysAdminCap &&
				conn.asyncCongestionThreshold > MaxUserCongestionThreshold {
				conn.asyncCongestionThreshold = MaxUserCongestionThreshold
			}
		}

		conn.asyncMu.Unlock()
	}

	return nil
}

// Abort this FUSE connection.
// It tries to acquire conn.fd.mu, conn.lock, conn.bgLock in order.
// All possible requests waiting or blocking will be aborted.
func (conn *connection) Abort(ctx context.Context) {
	conn.fd.mu.Lock()
	conn.mu.Lock()
	conn.asyncMu.Lock()

	if !conn.connected {
		conn.asyncMu.Unlock()
		conn.mu.Unlock()
		conn.fd.mu.Unlock()
		return
	}

	conn.connected = false

	// Empty the `fd.queue` that holds the requests
	// not yet read by the FUSE daemon yet.
	// These are a subset of the requests in `fuse.completion` map.
	for !conn.fd.queue.Empty() {
		req := conn.fd.queue.Front()
		conn.fd.queue.Remove(req)
	}

	var terminate []linux.FUSEOpID

	// 2. Collect the requests have not been sent to FUSE daemon,
	// or have not received a reply.
	for unique := range conn.fd.completions {
		terminate = append(terminate, unique)
	}

	// Release all locks to avoid deadlock.
	conn.asyncMu.Unlock()
	conn.mu.Unlock()
	conn.fd.mu.Unlock()

	// 1. The requets blocked before initialization.
	// Will reach call() `connected` check and return.
	if !conn.Initialized() {
		conn.SetInitialized()
	}

	// 2. Terminate the requests collected above.
	// Set ECONNABORTED error.
	// sendError() will remove them from `fd.completion` map.
	// Will enter the path of a normally received error.
	for _, toTerminate := range terminate {
		conn.fd.sendError(ctx, -int32(syscall.ECONNABORTED), toTerminate)
	}

	// 3. The requests not yet written to FUSE device.
	// Early terminate.
	// Will reach callFutureLocked() `connected` check and return.
	close(conn.fd.fullQueueCh)

	// TODO(gvisor.dev/issue/3528): Forget all pending forget reqs.
}
