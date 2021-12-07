// Copyright 2018 The gVisor Authors.
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
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/secio"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// pipeOperations are the fs.FileOperations of a host pipe.
//
// +stateify savable
type pipeOperations struct {
	fsutil.FilePipeSeek             `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	waiter.Queue

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
	var s unix.Stat_t
	if err := unix.Fstat(p.file.FD(), &s); err != nil {
		log.Warningf("pipe: cannot stat fd %d: %v", p.file.FD(), err)
		return unix.EINVAL
	}
	if (s.Mode & unix.S_IFMT) != unix.S_IFIFO {
		log.Warningf("pipe: cannot load fd %d as pipe, file type: %o", p.file.FD(), s.Mode)
		return unix.EINVAL
	}
	if err := unix.SetNonblock(p.file.FD(), true); err != nil {
		return err
	}
	return fdnotifier.AddFD(int32(p.file.FD()), &p.Queue)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (p *pipeOperations) EventRegister(e *waiter.Entry) error {
	p.Queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(int32(p.file.FD())); err != nil {
		p.Queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (p *pipeOperations) EventUnregister(e *waiter.Entry) {
	p.Queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(int32(p.file.FD())); err != nil {
		panic(fmt.Sprint("UpdateFD:", err))
	}
}

// Readiness returns a mask of ready events for stream.
func (p *pipeOperations) Readiness(mask waiter.EventMask) (eventMask waiter.EventMask) {
	return fdnotifier.NonBlockingPoll(int32(p.file.FD()), mask)
}

// Release implements fs.FileOperations.Release.
func (p *pipeOperations) Release(context.Context) {
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
		return total, linuxerr.ErrWouldBlock
	}
	return total, err
}

// Write implements fs.FileOperations.Write.
func (p *pipeOperations) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	n, err := src.CopyInTo(ctx, safemem.FromIOWriter{p.file})
	if err != nil && isBlockError(err) {
		return n, linuxerr.ErrWouldBlock
	}
	return n, err
}

// isBlockError unwraps os errors and checks if they are caused by EAGAIN or
// EWOULDBLOCK. This is so they can be transformed into linuxerr.ErrWouldBlock.
func isBlockError(err error) bool {
	if linuxerr.Equals(linuxerr.EAGAIN, err) || linuxerr.Equals(linuxerr.EWOULDBLOCK, err) {
		return true
	}
	if pe, ok := err.(*os.PathError); ok {
		return isBlockError(pe.Err)
	}
	return false
}
