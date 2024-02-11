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

package gofer

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
	"gvisor.dev/gvisor/pkg/sync"
)

var noHandle = handle{
	fdLisa: lisafs.ClientFD{}, // zero value is fine.
	fd:     -1,
}

// handle represents a remote "open file descriptor", consisting of an opened
// lisafs FD and optionally a host file descriptor.
//
// These are explicitly not savable.
type handle struct {
	fdLisa lisafs.ClientFD
	fd     int32 // -1 if unavailable
}

func (h *handle) close(ctx context.Context) {
	if h.fdLisa.Ok() {
		h.fdLisa.Close(ctx, true /* flush */)
	}
	if h.fd >= 0 {
		unix.Close(int(h.fd))
		h.fd = -1
	}
}

func (h *handle) readToBlocksAt(ctx context.Context, dsts safemem.BlockSeq, offset uint64) (uint64, error) {
	if dsts.IsEmpty() {
		return 0, nil
	}
	if h.fd >= 0 {
		ctx.UninterruptibleSleepStart()
		n, err := hostfd.Preadv2(h.fd, dsts, int64(offset), 0 /* flags */)
		ctx.UninterruptibleSleepFinish()
		return n, err
	}
	rw := getHandleReadWriter(ctx, h, int64(offset))
	defer putHandleReadWriter(rw)
	return safemem.FromIOReader{rw}.ReadToBlocks(dsts)
}

func (h *handle) writeFromBlocksAt(ctx context.Context, srcs safemem.BlockSeq, offset uint64) (uint64, error) {
	if srcs.IsEmpty() {
		return 0, nil
	}
	if h.fd >= 0 {
		ctx.UninterruptibleSleepStart()
		n, err := hostfd.Pwritev2(h.fd, srcs, int64(offset), 0 /* flags */)
		ctx.UninterruptibleSleepFinish()
		return n, err
	}
	rw := getHandleReadWriter(ctx, h, int64(offset))
	defer putHandleReadWriter(rw)
	return safemem.FromIOWriter{rw}.WriteFromBlocks(srcs)
}

func (h *handle) allocate(ctx context.Context, mode, offset, length uint64) error {
	if h.fdLisa.Ok() {
		return h.fdLisa.Allocate(ctx, mode, offset, length)
	}
	if h.fd >= 0 {
		return unix.Fallocate(int(h.fd), uint32(mode), int64(offset), int64(length))
	}
	return nil
}

func (h *handle) sync(ctx context.Context) error {
	// If we have a host FD, fsyncing it is likely to be faster than an fsync
	// RPC.
	if h.fd >= 0 {
		ctx.UninterruptibleSleepStart()
		err := unix.Fsync(int(h.fd))
		ctx.UninterruptibleSleepFinish()
		return err
	}
	if h.fdLisa.Ok() {
		return h.fdLisa.Sync(ctx)
	}
	return nil
}

type handleReadWriter struct {
	ctx context.Context
	h   *handle
	off uint64
}

var handleReadWriterPool = sync.Pool{
	New: func() any {
		return &handleReadWriter{}
	},
}

func getHandleReadWriter(ctx context.Context, h *handle, offset int64) *handleReadWriter {
	rw := handleReadWriterPool.Get().(*handleReadWriter)
	rw.ctx = ctx
	rw.h = h
	rw.off = uint64(offset)
	return rw
}

func putHandleReadWriter(rw *handleReadWriter) {
	rw.ctx = nil
	rw.h = nil
	handleReadWriterPool.Put(rw)
}

// Read implements io.Reader.Read.
func (rw *handleReadWriter) Read(dst []byte) (int, error) {
	n, err := rw.h.fdLisa.Read(rw.ctx, dst, rw.off)
	rw.off += n
	return int(n), err
}

// Write implements io.Writer.Write.
func (rw *handleReadWriter) Write(src []byte) (int, error) {
	n, err := rw.h.fdLisa.Write(rw.ctx, src, rw.off)
	rw.off += n
	return int(n), err
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (rw *handleReadWriter) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	n, err := rw.h.readToBlocksAt(rw.ctx, dsts, rw.off)
	rw.off += n
	return n, err
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
func (rw *handleReadWriter) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	n, err := rw.h.writeFromBlocksAt(rw.ctx, srcs, rw.off)
	rw.off += n
	return n, err
}
