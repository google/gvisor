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

package rdmaproxy

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/rdma"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// respPtrOffset is the offset within a write() command buffer of the
	// __u64 response pointer, for both command forms: every regular
	// command with a response begins with a __u64 response field
	// immediately following ib_uverbs_cmd_hdr, and extended commands
	// place it first in ib_uverbs_ex_cmd_hdr, which also immediately
	// follows ib_uverbs_cmd_hdr. Equal to SizeofIBUverbsCmdHdr.
	respPtrOffset = 8

	// maxWriteSize bounds command buffers copied into the sentry. Word
	// counts in ib_uverbs_cmd_hdr and ib_uverbs_ex_cmd_hdr are 16 bits, so
	// no valid command can exceed this.
	maxWriteSize = 1 << 21
)

// Write implements vfs.FileDescriptionImpl.Write.
//
// This is a passthrough proxy for the uverbs legacy write() command ABI
// (see ib_uverbs_write() in Linux's drivers/infiniband/core/uverbs_main.c).
// Commands are forwarded to the host device without an allowlist; the host
// kernel performs all command validation. The sentry intervenes only where
// the ABI is not address-space or fd-table transparent:
//
//   - The embedded __u64 response pointer is an application address that the
//     host kernel would otherwise dereference in the sentry's address space.
//     It is replaced with a sentry buffer, and the response is copied out to
//     the application afterwards. Whether a command has a response is
//     derived from the header: out_words > 0 for regular commands (every
//     such command's struct begins with the response pointer), and
//     out_words + provider_out_words > 0 for extended commands.
//
//   - Host fds returned in responses (GET_CONTEXT's async_fd,
//     CREATE_COMP_CHANNEL's fd) are imported into the calling task's fd
//     table and the response is rewritten accordingly.
//
//   - REG_MR's start address is an application buffer address that the host
//     kernel would pin in the sentry's address space (ib_umem_get). The
//     application range is pinned and mirrored into a sentry VA window, and
//     start is rewritten to the window (see rdma_fd_pin.go); the pins are
//     retained until DEREG_MR or Release.
//
// Commands whose driver payloads embed application buffer addresses
// (e.g. irdma's CREATE_CQ/CREATE_QP driver data) are still forwarded as-is
// and fail until they receive the same treatment.
func (fd *rdmaFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	if fd.isRestored() {
		return 0, linuxerr.EIO
	}
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		return 0, linuxerr.EINVAL
	}
	size := src.NumBytes()
	if size < int64(rdma.SizeofIBUverbsCmdHdr) || size > maxWriteSize {
		return 0, linuxerr.EINVAL
	}
	buf := make([]byte, size)
	if _, err := src.CopyIn(ctx, buf); err != nil {
		return 0, err
	}

	var hdr rdma.IBUverbsCmdHdr
	hdr.UnmarshalBytes(buf)
	if hdr.Command&^uint32(rdma.IB_USER_VERBS_CMD_COMMAND_MASK|rdma.IB_USER_VERBS_CMD_FLAG_EXTENDED) != 0 {
		return 0, linuxerr.EINVAL
	}
	cmd := hdr.Command & rdma.IB_USER_VERBS_CMD_COMMAND_MASK
	extended := hdr.Command&rdma.IB_USER_VERBS_CMD_FLAG_EXTENDED != 0

	var (
		respSize     uint32
		patchResp    bool
		guestRespPtr hostarch.Addr
		pins         pendingPins
	)
	if !extended {
		respSize = uint32(hdr.OutWords) * 4
		// A command buffer too short to hold the response pointer is
		// rejected by the host kernel before the pointer is read
		// (verify_hdr() returns ENOSPC), so it can be forwarded
		// unpatched.
		if respSize > 0 && len(buf) < respPtrOffset+8 {
			respSize = 0
		}
		if respSize > 0 {
			guestRespPtr = hostarch.Addr(hostarch.ByteOrder.Uint64(buf[respPtrOffset:]))
			patchResp = true
		}
		if cmd == rdma.IB_USER_VERBS_CMD_REG_MR {
			if err := pins.setupRegMR(ctx, t, buf); err != nil {
				return 0, err
			}
		}
	} else {
		hdrsSize := int(rdma.SizeofIBUverbsCmdHdr) + int(rdma.SizeofIBUverbsExCmdHdr)
		if len(buf) >= hdrsSize {
			var exHdr rdma.IBUverbsExCmdHdr
			exHdr.UnmarshalBytes(buf[rdma.SizeofIBUverbsCmdHdr:])
			respSize = (uint32(hdr.OutWords) + uint32(exHdr.ProviderOutWords)) * 8
			// Mirror ib_uverbs_write(): a response pointer must be
			// present iff a response is requested. This must be
			// checked here because patching would otherwise mask
			// the inconsistency from the host kernel.
			if (exHdr.Response == 0) != (respSize == 0) {
				return 0, linuxerr.EINVAL
			}
			if respSize > 0 {
				guestRespPtr = hostarch.Addr(exHdr.Response)
				patchResp = true
			}
		}
		// Buffers shorter than the two headers are rejected by the
		// host kernel (EINVAL); forward unpatched.
	}

	var respBuf []byte
	if respSize > 0 {
		respBuf = make([]byte, respSize)
	}
	if err := rdmaWriteInvoke(fd.hostFD, buf, respBuf, patchResp); err != nil {
		pins.abort()
		return 0, err
	}

	// The MR now exists host-side; record its pins before anything below
	// can fail, so that Release reclaims them even if the application
	// never learns the handle. The host kernel enforces out_words for
	// REG_MR (uverbs_response returns ENOSPC otherwise), so on success
	// respBuf always holds the full response.
	if !extended && cmd == rdma.IB_USER_VERBS_CMD_REG_MR && len(respBuf) >= int(rdma.SizeofIBUverbsRegMRResp) {
		var resp rdma.IBUverbsRegMRResp
		resp.UnmarshalBytes(respBuf)
		fd.saveMR(resp.MRHandle, pins.commit())
	}

	if len(respBuf) > 0 {
		if post := respPostProcess(cmd, extended); post != nil {
			if err := post(ctx, t, respBuf); err != nil {
				return 0, err
			}
		}
		if _, err := t.CopyOutBytes(guestRespPtr, respBuf); err != nil {
			return 0, err
		}
	}
	if !extended && cmd == rdma.IB_USER_VERBS_CMD_DEREG_MR && len(buf) >= int(rdma.SizeofIBUverbsCmdHdr+rdma.SizeofIBUverbsDeregMR) {
		var dereg rdma.IBUverbsDeregMR
		dereg.UnmarshalBytes(buf[rdma.SizeofIBUverbsCmdHdr:])
		fd.forgetMR(dereg.MRHandle)
	}
	ctx.Debugf("rdmaproxy: proxied write command %d (extended=%t), req %d bytes, resp %d bytes", cmd, extended, len(buf), respSize)
	return int64(len(buf)), nil
}

// respPostProcess returns the response post-processing hook for commands
// whose responses are not fd-table transparent, or nil.
func respPostProcess(cmd uint32, extended bool) func(context.Context, *kernel.Task, []byte) error {
	if extended {
		return nil
	}
	switch cmd {
	case rdma.IB_USER_VERBS_CMD_GET_CONTEXT:
		return postGetContext
	case rdma.IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL:
		return postCreateCompChannel
	}
	return nil
}

// importHostFD installs a host fd returned by a uverbs command (owned by
// the sentry) into the calling task's fd table and returns the resulting
// application fd. The host fd is consumed in all cases. The host kernel
// creates these fds with O_CLOEXEC (see ib_uverbs_get_context() and
// ib_uverbs_create_comp_channel() in drivers/infiniband/core/uverbs_cmd.c),
// so the application fd is too.
func importHostFD(ctx context.Context, t *kernel.Task, hostFD int) (int32, error) {
	file, err := host.NewFD(ctx, t.Kernel().HostMount(), hostFD, &host.NewFDOptions{})
	if err != nil {
		unix.Close(hostFD)
		return -1, err
	}
	defer file.DecRef(ctx)
	return t.NewFDFrom(0, file, kernel.FDFlags{CloseOnExec: true})
}

// postGetContext handles the GET_CONTEXT response: the async_fd returned by
// the host kernel is a host fd owned by the sentry, so it is installed into
// the calling task's fd table and the response is rewritten to refer to the
// resulting application fd.
func postGetContext(ctx context.Context, t *kernel.Task, respBuf []byte) error {
	if len(respBuf) < int(rdma.SizeofIBUverbsGetContextResp) {
		return linuxerr.EINVAL
	}
	var resp rdma.IBUverbsGetContextResp
	resp.UnmarshalBytes(respBuf)
	if int32(resp.AsyncFD) < 0 {
		return linuxerr.EINVAL
	}
	appFD, err := importHostFD(ctx, t, int(resp.AsyncFD))
	if err != nil {
		return err
	}
	resp.AsyncFD = uint32(appFD)
	resp.MarshalBytes(respBuf)
	return nil
}

// postCreateCompChannel handles the CREATE_COMP_CHANNEL response
// analogously to postGetContext.
func postCreateCompChannel(ctx context.Context, t *kernel.Task, respBuf []byte) error {
	if len(respBuf) < int(rdma.SizeofIBUverbsCreateCompChannelResp) {
		return linuxerr.EINVAL
	}
	var resp rdma.IBUverbsCreateCompChannelResp
	resp.UnmarshalBytes(respBuf)
	if int32(resp.FD) < 0 {
		return linuxerr.EINVAL
	}
	appFD, err := importHostFD(ctx, t, int(resp.FD))
	if err != nil {
		return err
	}
	resp.FD = uint32(appFD)
	resp.MarshalBytes(respBuf)
	return nil
}
