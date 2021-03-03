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

package fdpipe

import (
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// NonBlockingOpener is a generic host file opener used to retry opening host
// pipes if necessary.
type NonBlockingOpener interface {
	// NonBlockingOpen tries to open a host pipe in a non-blocking way,
	// and otherwise returns an error. Implementations should be idempotent.
	NonBlockingOpen(context.Context, fs.PermMask) (*fd.FD, error)
}

// Open blocks until a host pipe can be opened or the action was cancelled.
// On success, returns fs.FileOperations wrapping the opened host pipe.
func Open(ctx context.Context, opener NonBlockingOpener, flags fs.FileFlags) (fs.FileOperations, error) {
	p := &pipeOpenState{}
	canceled := false
	for {
		if file, err := p.TryOpen(ctx, opener, flags); err != syserror.ErrWouldBlock {
			return file, err
		}

		// Honor the cancellation request if open still blocks.
		if canceled {
			// If we were canceled but we have a handle to a host
			// file, we need to close it.
			if p.hostFile != nil {
				p.hostFile.Close()
			}
			return nil, syserror.ErrInterrupted
		}

		cancel := ctx.SleepStart()
		select {
		case <-cancel:
			// The cancellation request received here really says
			// "cancel from now on (or ASAP)". Any environmental
			// changes happened before receiving it, that might have
			// caused open to not block anymore, should still be
			// respected. So we cannot just return here. We have to
			// give open another try below first.
			canceled = true
			ctx.SleepFinish(false)
		case <-time.After(100 * time.Millisecond):
			// If we would block, then delay retrying for a bit, since there
			// is no way to know when the pipe would be ready to be
			// re-opened. This is identical to sending an event notification
			// to stop blocking in Task.Block, given that this routine will
			// stop retrying if a cancelation is received.
			ctx.SleepFinish(true)
		}
	}
}

// pipeOpenState holds state needed to open a blocking named pipe read only, for instance the
// file that has been opened but doesn't yet have a corresponding writer.
type pipeOpenState struct {
	// hostFile is the read only named pipe which lacks a corresponding writer.
	hostFile *fd.FD
}

// unwrapError is needed to match against ENXIO primarily.
func unwrapError(err error) error {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err
	}
	return err
}

// TryOpen uses a NonBlockingOpener to try to open a host pipe, respecting the fs.FileFlags.
func (p *pipeOpenState) TryOpen(ctx context.Context, opener NonBlockingOpener, flags fs.FileFlags) (*pipeOperations, error) {
	switch {
	// Reject invalid configurations so they don't accidentally succeed below.
	case !flags.Read && !flags.Write:
		return nil, unix.EINVAL

	// Handle opening RDWR or with O_NONBLOCK: will never block, so try only once.
	case (flags.Read && flags.Write) || flags.NonBlocking:
		f, err := opener.NonBlockingOpen(ctx, fs.PermMask{Read: flags.Read, Write: flags.Write})
		if err != nil {
			return nil, err
		}
		return newPipeOperations(ctx, opener, flags, f, nil)

	// Handle opening O_WRONLY blocking: convert ENXIO to syserror.ErrWouldBlock.
	// See TryOpenWriteOnly for more details.
	case flags.Write:
		return p.TryOpenWriteOnly(ctx, opener)

	default:
		// Handle opening O_RDONLY blocking: convert EOF from read to syserror.ErrWouldBlock.
		// See TryOpenReadOnly for more details.
		return p.TryOpenReadOnly(ctx, opener)
	}
}

// TryOpenReadOnly tries to open a host pipe read only but only returns a fs.File when
// there is a coordinating writer.  Call TryOpenReadOnly repeatedly on the same pipeOpenState
// until syserror.ErrWouldBlock is no longer returned.
//
// How it works:
//
// Opening a pipe read only will return no error, but each non zero Read will return EOF
// until a writer becomes available, then EWOULDBLOCK.  This is the only state change
// available to us.  We keep a read ahead buffer in case we read bytes instead of getting
// EWOULDBLOCK, to be read from on the first read request to this fs.File.
func (p *pipeOpenState) TryOpenReadOnly(ctx context.Context, opener NonBlockingOpener) (*pipeOperations, error) {
	// Waiting for a blocking read only open involves reading from the host pipe until
	// bytes or other writers are available, so instead of retrying opening the pipe,
	// it's necessary to retry reading from the pipe. To do this we need to keep around
	// the read only pipe we opened, until success or an irrecoverable read error (at
	// which point it must be closed).
	if p.hostFile == nil {
		var err error
		p.hostFile, err = opener.NonBlockingOpen(ctx, fs.PermMask{Read: true})
		if err != nil {
			return nil, err
		}
	}

	// Try to read from the pipe to see if writers are around.
	tryReadBuffer := make([]byte, 1)
	n, rerr := p.hostFile.Read(tryReadBuffer)

	// No bytes were read.
	if n == 0 {
		// EOF means that we're not ready yet.
		if rerr == nil || rerr == io.EOF {
			return nil, syserror.ErrWouldBlock
		}
		// Any error that is not EWOULDBLOCK also means we're not
		// ready yet, and probably never will be ready.  In this
		// case we need to close the host pipe we opened.
		if unwrapError(rerr) != unix.EWOULDBLOCK {
			p.hostFile.Close()
			return nil, rerr
		}
	}

	// If any bytes were read, no matter the corresponding error, we need
	// to keep them around so they can be read by the application.
	var readAheadBuffer []byte
	if n > 0 {
		readAheadBuffer = tryReadBuffer
	}

	// Successfully opened read only blocking pipe with either bytes available
	// to read and/or a writer available.
	return newPipeOperations(ctx, opener, fs.FileFlags{Read: true}, p.hostFile, readAheadBuffer)
}

// TryOpenWriteOnly tries to open a host pipe write only but only returns a fs.File when
// there is a coordinating reader.  Call TryOpenWriteOnly repeatedly on the same pipeOpenState
// until syserror.ErrWouldBlock is no longer returned.
//
// How it works:
//
// Opening a pipe write only will return ENXIO until readers are available.  Converts the ENXIO
// to an syserror.ErrWouldBlock, to tell callers to retry.
func (*pipeOpenState) TryOpenWriteOnly(ctx context.Context, opener NonBlockingOpener) (*pipeOperations, error) {
	hostFile, err := opener.NonBlockingOpen(ctx, fs.PermMask{Write: true})
	if unwrapError(err) == unix.ENXIO {
		return nil, syserror.ErrWouldBlock
	}
	if err != nil {
		return nil, err
	}
	return newPipeOperations(ctx, opener, fs.FileFlags{Write: true}, hostFile, nil)
}
