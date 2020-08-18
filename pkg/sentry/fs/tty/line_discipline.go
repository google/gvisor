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

package tty

import (
	"bytes"
	"unicode/utf8"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// LINT.IfChange

const (
	// canonMaxBytes is the number of bytes that fit into a single line of
	// terminal input in canonical mode. This corresponds to N_TTY_BUF_SIZE
	// in include/linux/tty.h.
	canonMaxBytes = 4096

	// nonCanonMaxBytes is the maximum number of bytes that can be read at
	// a time in noncanonical mode.
	nonCanonMaxBytes = canonMaxBytes - 1

	spacesPerTab = 8
)

// lineDiscipline dictates how input and output are handled between the
// pseudoterminal (pty) master and slave. It can be configured to alter I/O,
// modify control characters (e.g. Ctrl-C for SIGINT), etc. The following man
// pages are good resources for how to affect the line discipline:
//
//   * termios(3)
//   * tty_ioctl(4)
//
// This file corresponds most closely to drivers/tty/n_tty.c.
//
// lineDiscipline has a simple structure but supports a multitude of options
// (see the above man pages). It consists of two queues of bytes: one from the
// terminal master to slave (the input queue) and one from slave to master (the
// output queue). When bytes are written to one end of the pty, the line
// discipline reads the bytes, modifies them or takes special action if
// required, and enqueues them to be read by the other end of the pty:
//
//       input from terminal    +-------------+   input to process (e.g. bash)
//    +------------------------>| input queue |---------------------------+
//    |   (inputQueueWrite)     +-------------+     (inputQueueRead)      |
//    |                                                                   |
//    |                                                                   v
// masterFD                                                            slaveFD
//    ^                                                                   |
//    |                                                                   |
//    |   output to terminal   +--------------+    output from process    |
//    +------------------------| output queue |<--------------------------+
//        (outputQueueRead)    +--------------+    (outputQueueWrite)
//
// Lock order:
//  termiosMu
//    inQueue.mu
//      outQueue.mu
//
// +stateify savable
type lineDiscipline struct {
	// sizeMu protects size.
	sizeMu sync.Mutex `state:"nosave"`

	// size is the terminal size (width and height).
	size linux.WindowSize

	// inQueue is the input queue of the terminal.
	inQueue queue

	// outQueue is the output queue of the terminal.
	outQueue queue

	// termiosMu protects termios.
	termiosMu sync.RWMutex `state:"nosave"`

	// termios is the terminal configuration used by the lineDiscipline.
	termios linux.KernelTermios

	// column is the location in a row of the cursor. This is important for
	// handling certain special characters like backspace.
	column int

	// masterWaiter is used to wait on the master end of the TTY.
	masterWaiter waiter.Queue `state:"zerovalue"`

	// slaveWaiter is used to wait on the slave end of the TTY.
	slaveWaiter waiter.Queue `state:"zerovalue"`
}

func newLineDiscipline(termios linux.KernelTermios) *lineDiscipline {
	ld := lineDiscipline{termios: termios}
	ld.inQueue.transformer = &inputQueueTransformer{}
	ld.outQueue.transformer = &outputQueueTransformer{}
	return &ld
}

// getTermios gets the linux.Termios for the tty.
func (l *lineDiscipline) getTermios(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	l.termiosMu.RLock()
	defer l.termiosMu.RUnlock()
	// We must copy a Termios struct, not KernelTermios.
	t := l.termios.ToTermios()
	_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), t, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	return 0, err
}

// setTermios sets a linux.Termios for the tty.
func (l *lineDiscipline) setTermios(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	l.termiosMu.Lock()
	defer l.termiosMu.Unlock()
	oldCanonEnabled := l.termios.LEnabled(linux.ICANON)
	// We must copy a Termios struct, not KernelTermios.
	var t linux.Termios
	_, err := usermem.CopyObjectIn(ctx, io, args[2].Pointer(), &t, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	l.termios.FromTermios(t)

	// If canonical mode is turned off, move bytes from inQueue's wait
	// buffer to its read buffer. Anything already in the read buffer is
	// now readable.
	if oldCanonEnabled && !l.termios.LEnabled(linux.ICANON) {
		l.inQueue.mu.Lock()
		l.inQueue.pushWaitBufLocked(l)
		l.inQueue.readable = true
		l.inQueue.mu.Unlock()
		l.slaveWaiter.Notify(waiter.EventIn)
	}

	return 0, err
}

func (l *lineDiscipline) windowSize(ctx context.Context, io usermem.IO, args arch.SyscallArguments) error {
	l.sizeMu.Lock()
	defer l.sizeMu.Unlock()
	_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), l.size, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	return err
}

func (l *lineDiscipline) setWindowSize(ctx context.Context, io usermem.IO, args arch.SyscallArguments) error {
	l.sizeMu.Lock()
	defer l.sizeMu.Unlock()
	_, err := usermem.CopyObjectIn(ctx, io, args[2].Pointer(), &l.size, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	return err
}

func (l *lineDiscipline) masterReadiness() waiter.EventMask {
	// We don't have to lock a termios because the default master termios
	// is immutable.
	return l.inQueue.writeReadiness(&linux.MasterTermios) | l.outQueue.readReadiness(&linux.MasterTermios)
}

func (l *lineDiscipline) slaveReadiness() waiter.EventMask {
	l.termiosMu.RLock()
	defer l.termiosMu.RUnlock()
	return l.outQueue.writeReadiness(&l.termios) | l.inQueue.readReadiness(&l.termios)
}

func (l *lineDiscipline) inputQueueReadSize(ctx context.Context, io usermem.IO, args arch.SyscallArguments) error {
	return l.inQueue.readableSize(ctx, io, args)
}

func (l *lineDiscipline) inputQueueRead(ctx context.Context, dst usermem.IOSequence) (int64, error) {
	l.termiosMu.RLock()
	defer l.termiosMu.RUnlock()
	n, pushed, err := l.inQueue.read(ctx, dst, l)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		l.masterWaiter.Notify(waiter.EventOut)
		if pushed {
			l.slaveWaiter.Notify(waiter.EventIn)
		}
		return n, nil
	}
	return 0, syserror.ErrWouldBlock
}

func (l *lineDiscipline) inputQueueWrite(ctx context.Context, src usermem.IOSequence) (int64, error) {
	l.termiosMu.RLock()
	defer l.termiosMu.RUnlock()
	n, err := l.inQueue.write(ctx, src, l)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		l.slaveWaiter.Notify(waiter.EventIn)
		return n, nil
	}
	return 0, syserror.ErrWouldBlock
}

func (l *lineDiscipline) outputQueueReadSize(ctx context.Context, io usermem.IO, args arch.SyscallArguments) error {
	return l.outQueue.readableSize(ctx, io, args)
}

func (l *lineDiscipline) outputQueueRead(ctx context.Context, dst usermem.IOSequence) (int64, error) {
	l.termiosMu.RLock()
	defer l.termiosMu.RUnlock()
	n, pushed, err := l.outQueue.read(ctx, dst, l)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		l.slaveWaiter.Notify(waiter.EventOut)
		if pushed {
			l.masterWaiter.Notify(waiter.EventIn)
		}
		return n, nil
	}
	return 0, syserror.ErrWouldBlock
}

func (l *lineDiscipline) outputQueueWrite(ctx context.Context, src usermem.IOSequence) (int64, error) {
	l.termiosMu.RLock()
	defer l.termiosMu.RUnlock()
	n, err := l.outQueue.write(ctx, src, l)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		l.masterWaiter.Notify(waiter.EventIn)
		return n, nil
	}
	return 0, syserror.ErrWouldBlock
}

// transformer is a helper interface to make it easier to stateify queue.
type transformer interface {
	// transform functions require queue's mutex to be held.
	transform(*lineDiscipline, *queue, []byte) int
}

// outputQueueTransformer implements transformer. It performs line discipline
// transformations on the output queue.
//
// +stateify savable
type outputQueueTransformer struct{}

// transform does output processing for one end of the pty. See
// drivers/tty/n_tty.c:do_output_char for an analogous kernel function.
//
// Preconditions:
// * l.termiosMu must be held for reading.
// * q.mu must be held.
func (*outputQueueTransformer) transform(l *lineDiscipline, q *queue, buf []byte) int {
	// transformOutput is effectively always in noncanonical mode, as the
	// master termios never has ICANON set.

	if !l.termios.OEnabled(linux.OPOST) {
		q.readBuf = append(q.readBuf, buf...)
		if len(q.readBuf) > 0 {
			q.readable = true
		}
		return len(buf)
	}

	var ret int
	for len(buf) > 0 {
		size := l.peek(buf)
		cBytes := append([]byte{}, buf[:size]...)
		ret += size
		buf = buf[size:]
		// We're guaranteed that cBytes has at least one element.
		switch cBytes[0] {
		case '\n':
			if l.termios.OEnabled(linux.ONLRET) {
				l.column = 0
			}
			if l.termios.OEnabled(linux.ONLCR) {
				q.readBuf = append(q.readBuf, '\r', '\n')
				continue
			}
		case '\r':
			if l.termios.OEnabled(linux.ONOCR) && l.column == 0 {
				continue
			}
			if l.termios.OEnabled(linux.OCRNL) {
				cBytes[0] = '\n'
				if l.termios.OEnabled(linux.ONLRET) {
					l.column = 0
				}
				break
			}
			l.column = 0
		case '\t':
			spaces := spacesPerTab - l.column%spacesPerTab
			if l.termios.OutputFlags&linux.TABDLY == linux.XTABS {
				l.column += spaces
				q.readBuf = append(q.readBuf, bytes.Repeat([]byte{' '}, spacesPerTab)...)
				continue
			}
			l.column += spaces
		case '\b':
			if l.column > 0 {
				l.column--
			}
		default:
			l.column++
		}
		q.readBuf = append(q.readBuf, cBytes...)
	}
	if len(q.readBuf) > 0 {
		q.readable = true
	}
	return ret
}

// inputQueueTransformer implements transformer. It performs line discipline
// transformations on the input queue.
//
// +stateify savable
type inputQueueTransformer struct{}

// transform does input processing for one end of the pty. Characters read are
// transformed according to flags set in the termios struct. See
// drivers/tty/n_tty.c:n_tty_receive_char_special for an analogous kernel
// function.
//
// Preconditions:
// * l.termiosMu must be held for reading.
// * q.mu must be held.
func (*inputQueueTransformer) transform(l *lineDiscipline, q *queue, buf []byte) int {
	// If there's a line waiting to be read in canonical mode, don't write
	// anything else to the read buffer.
	if l.termios.LEnabled(linux.ICANON) && q.readable {
		return 0
	}

	maxBytes := nonCanonMaxBytes
	if l.termios.LEnabled(linux.ICANON) {
		maxBytes = canonMaxBytes
	}

	var ret int
	for len(buf) > 0 && len(q.readBuf) < canonMaxBytes {
		size := l.peek(buf)
		cBytes := append([]byte{}, buf[:size]...)
		// We're guaranteed that cBytes has at least one element.
		switch cBytes[0] {
		case '\r':
			if l.termios.IEnabled(linux.IGNCR) {
				buf = buf[size:]
				ret += size
				continue
			}
			if l.termios.IEnabled(linux.ICRNL) {
				cBytes[0] = '\n'
			}
		case '\n':
			if l.termios.IEnabled(linux.INLCR) {
				cBytes[0] = '\r'
			}
		}

		// In canonical mode, we discard non-terminating characters
		// after the first 4095.
		if l.shouldDiscard(q, cBytes) {
			buf = buf[size:]
			ret += size
			continue
		}

		// Stop if the buffer would be overfilled.
		if len(q.readBuf)+size > maxBytes {
			break
		}
		buf = buf[size:]
		ret += size

		// If we get EOF, make the buffer available for reading.
		if l.termios.LEnabled(linux.ICANON) && l.termios.IsEOF(cBytes[0]) {
			q.readable = true
			break
		}

		q.readBuf = append(q.readBuf, cBytes...)

		// Anything written to the readBuf will have to be echoed.
		if l.termios.LEnabled(linux.ECHO) {
			l.outQueue.writeBytes(cBytes, l)
			l.masterWaiter.Notify(waiter.EventIn)
		}

		// If we finish a line, make it available for reading.
		if l.termios.LEnabled(linux.ICANON) && l.termios.IsTerminating(cBytes) {
			q.readable = true
			break
		}
	}

	// In noncanonical mode, everything is readable.
	if !l.termios.LEnabled(linux.ICANON) && len(q.readBuf) > 0 {
		q.readable = true
	}

	return ret
}

// shouldDiscard returns whether c should be discarded. In canonical mode, if
// too many bytes are enqueued, we keep reading input and discarding it until
// we find a terminating character. Signal/echo processing still occurs.
//
// Precondition:
// * l.termiosMu must be held for reading.
// * q.mu must be held.
func (l *lineDiscipline) shouldDiscard(q *queue, cBytes []byte) bool {
	return l.termios.LEnabled(linux.ICANON) && len(q.readBuf)+len(cBytes) >= canonMaxBytes && !l.termios.IsTerminating(cBytes)
}

// peek returns the size in bytes of the next character to process. As long as
// b isn't empty, peek returns a value of at least 1.
func (l *lineDiscipline) peek(b []byte) int {
	size := 1
	// If UTF-8 support is enabled, runes might be multiple bytes.
	if l.termios.IEnabled(linux.IUTF8) {
		_, size = utf8.DecodeRune(b)
	}
	return size
}

// LINT.ThenChange(../../fsimpl/devpts/line_discipline.go)
