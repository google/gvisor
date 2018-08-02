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

// Package fdpipe implements common namedpipe opening and accessing logic.
package fdpipe

import (
	"os"
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/fd"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/secio"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
	"gvisor.googlesource.com/gvisor/pkg/waiter/fdnotifier"
)

// pipeOperations are the fs.FileOperations of a host pipe.
//
// +stateify savable
type pipeOperations struct {
	fsutil.PipeSeek      `state:"nosave"`
	fsutil.NotDirReaddir `state:"nosave"`
	fsutil.NoFsync       `state:"nosave"`
	fsutil.NoopFlush     `state:"nosave"`
	fsutil.NoMMap        `state:"nosave"`
	fsutil.NoIoctl       `state:"nosave"`
	waiter.Queue         `state:"nosave"`

	// flags are the flags used to open the pipe.
	flags fs.FileFlags `state:".(fs.FileFlags)"`

	// opener is how the pipe was opened.
	opener NonBlockingOpener `state:"wait"`

	// file represents the host pipe.
	file *fd.FD `state:"nosave"`

	// mu protects readAheadBuffer access below.
	mu sync.Mutex `state:"nosave"`

	// readAheadBuffer contains read bytes that have not yet been read
	// by the application but need to be buffered for save-restore for correct
	// opening semantics.  The readAheadBuffer will only be non-empty when the
	// is first opened and will be drained by subsequent reads on the pipe.
	readAheadBuffer []byte
}

// newPipeOperations returns an implementation of fs.FileOperations for a pipe.
func newPipeOperations(ctx context.Context, opener NonBlockingOpener, flags fs.FileFlags, file *fd.FD, readAheadBuffer []byte) (*pipeOperations, error) {
	pipeOps := &pipeOperations{
		flags:           flags,
		opener:          opener,
		file:            file,
		readAheadBuffer: readAheadBuffer,
	}
	if err := pipeOps.init(); err != nil {
		return nil, err
	}
	return pipeOps, nil
}

// init initializes p.file.
func (p *pipeOperations) init() error {
	var s syscall.Stat_t
	if err := syscall.Fstat(p.file.FD(), &s); err != nil {
		log.Warningf("pipe: cannot stat fd %d: %v", p.file.FD(), err)
		return syscall.EINVAL
	}
	if s.Mode&syscall.S_IFIFO != syscall.S_IFIFO {
		log.Warningf("pipe: cannot load fd %d as pipe, file type: %o", p.file.FD(), s.Mode)
		return syscall.EINVAL
	}
	if err := syscall.SetNonblock(p.file.FD(), true); err != nil {
		return err
	}
	return fdnotifier.AddFD(int32(p.file.FD()), &p.Queue)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (p *pipeOperations) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	p.Queue.EventRegister(e, mask)
	fdnotifier.UpdateFD(int32(p.file.FD()))
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (p *pipeOperations) EventUnregister(e *waiter.Entry) {
	p.Queue.EventUnregister(e)
	fdnotifier.UpdateFD(int32(p.file.FD()))
}

// Readiness returns a mask of ready events for stream.
func (p *pipeOperations) Readiness(mask waiter.EventMask) (eventMask waiter.EventMask) {
	return fdnotifier.NonBlockingPoll(int32(p.file.FD()), mask)
}

// Release implements fs.FileOperations.Release.
func (p *pipeOperations) Release() {
	fdnotifier.RemoveFD(int32(p.file.FD()))
	p.file.Close()
	p.file = nil
}

// Read implements fs.FileOperations.Read.
func (p *pipeOperations) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	// Drain the read ahead buffer, if it contains anything first.
	var bufN int
	var bufErr error
	p.mu.Lock()
	if len(p.readAheadBuffer) > 0 {
		bufN, bufErr = dst.CopyOut(ctx, p.readAheadBuffer)
		p.readAheadBuffer = p.readAheadBuffer[bufN:]
		dst = dst.DropFirst(bufN)
	}
	p.mu.Unlock()
	if dst.NumBytes() == 0 || bufErr != nil {
		return int64(bufN), bufErr
	}

	// Pipes expect full reads.
	n, err := dst.CopyOutFrom(ctx, safemem.FromIOReader{secio.FullReader{p.file}})
	total := int64(bufN) + n
	if err != nil && isBlockError(err) {
		return total, syserror.ErrWouldBlock
	}
	return total, err
}

// Write implements fs.FileOperations.Write.
func (p *pipeOperations) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	n, err := src.CopyInTo(ctx, safemem.FromIOWriter{p.file})
	if err != nil && isBlockError(err) {
		return n, syserror.ErrWouldBlock
	}
	return n, err
}

// isBlockError unwraps os errors and checks if they are caused by EAGAIN or
// EWOULDBLOCK. This is so they can be transformed into syserror.ErrWouldBlock.
func isBlockError(err error) bool {
	if err == syserror.EAGAIN || err == syserror.EWOULDBLOCK {
		return true
	}
	if pe, ok := err.(*os.PathError); ok {
		return isBlockError(pe.Err)
	}
	return false
}
