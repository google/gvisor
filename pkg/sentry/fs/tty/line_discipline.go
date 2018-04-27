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

package tty

import (
	"bytes"
	"sync"
	"unicode/utf8"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

const (
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
//    |                         +-------------+                           |
//    |                                                                   |
//    |                                                                   v
// masterFD                                                            slaveFD
//    ^                                                                   |
//    |                                                                   |
//    |   output to terminal   +--------------+    output from process    |
//    +------------------------| output queue |<--------------------------+
//                             +--------------+
//
// Lock order:
//  inMu
//    outMu
//      termiosMu
type lineDiscipline struct {
	// inMu protects inQueue.
	inMu sync.Mutex `state:"nosave"`

	// inQueue is the input queue of the terminal.
	inQueue queue

	// outMu protects outQueue.
	outMu sync.Mutex `state:"nosave"`

	// outQueue is the output queue of the terminal.
	outQueue queue

	// termiosMu protects termios.
	termiosMu sync.Mutex `state:"nosave"`

	// termios is the terminal configuration used by the lineDiscipline.
	termios linux.KernelTermios

	// column is the location in a row of the cursor. This is important for
	// handling certain special characters like backspace.
	column int
}

// getTermios gets the linux.Termios for the tty.
func (l *lineDiscipline) getTermios(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	l.termiosMu.Lock()
	defer l.termiosMu.Unlock()
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
	// We must copy a Termios struct, not KernelTermios.
	var t linux.Termios
	_, err := usermem.CopyObjectIn(ctx, io, args[2].Pointer(), &t, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	l.termios.FromTermios(t)
	return 0, err
}

func (l *lineDiscipline) masterReadiness() waiter.EventMask {
	l.inMu.Lock()
	defer l.inMu.Unlock()
	l.outMu.Lock()
	defer l.outMu.Unlock()
	return l.inQueue.writeReadiness() | l.outQueue.readReadiness()
}

func (l *lineDiscipline) slaveReadiness() waiter.EventMask {
	l.inMu.Lock()
	defer l.inMu.Unlock()
	l.outMu.Lock()
	defer l.outMu.Unlock()
	return l.outQueue.writeReadiness() | l.inQueue.readReadiness()
}

// queue represents one of the input or output queues between a pty master and
// slave.
type queue struct {
	waiter.Queue `state:"nosave"`
	buf          bytes.Buffer `state:".([]byte)"`
}

// saveBuf is invoked by stateify.
func (q *queue) saveBuf() []byte {
	return append([]byte(nil), q.buf.Bytes()...)
}

// loadBuf is invoked by stateify.
func (q *queue) loadBuf(b []byte) {
	q.buf.Write(b)
}

// readReadiness returns whether q is ready to be read from.
//
// Preconditions: q's mutex must be held.
func (q *queue) readReadiness() waiter.EventMask {
	ready := waiter.EventMask(0)
	if q.buf.Len() > 0 {
		ready |= waiter.EventIn
	}
	return ready
}

// writeReadiness returns whether q is ready to be written to.
func (q *queue) writeReadiness() waiter.EventMask {
	return waiter.EventOut
}

func (l *lineDiscipline) inputQueueRead(ctx context.Context, dst usermem.IOSequence) (int64, error) {
	l.inMu.Lock()
	defer l.inMu.Unlock()
	return l.queueRead(ctx, dst, &l.inQueue)
}

func (l *lineDiscipline) inputQueueWrite(ctx context.Context, src usermem.IOSequence) (int64, error) {
	l.inMu.Lock()
	defer l.inMu.Unlock()
	return l.queueWrite(ctx, src, &l.inQueue, false)
}

func (l *lineDiscipline) outputQueueRead(ctx context.Context, dst usermem.IOSequence) (int64, error) {
	l.outMu.Lock()
	defer l.outMu.Unlock()
	return l.queueRead(ctx, dst, &l.outQueue)
}

func (l *lineDiscipline) outputQueueWrite(ctx context.Context, src usermem.IOSequence) (int64, error) {
	l.outMu.Lock()
	defer l.outMu.Unlock()
	return l.queueWrite(ctx, src, &l.outQueue, true)
}

// queueRead reads from q to userspace.
//
// Preconditions: q's lock must be held.
func (l *lineDiscipline) queueRead(ctx context.Context, dst usermem.IOSequence, q *queue) (int64, error) {
	// Copy bytes out to user-space. queueRead doesn't have to do any
	// processing or other extra work -- that's all taken care of when
	// writing to a queue.
	n, err := q.buf.WriteTo(dst.Writer(ctx))

	// If state changed, notify any waiters. If nothing was available to
	// read, let the caller know we could block.
	if n > 0 {
		q.Notify(waiter.EventOut)
	} else if err == nil {
		return 0, syserror.ErrWouldBlock
	}
	return int64(n), err
}

// queueWrite writes to q from userspace. `output` is whether the queue being
// written to should be subject to output processing (i.e. whether it is the
// output queue).
//
// Precondition: q's lock must be held.
func (l *lineDiscipline) queueWrite(ctx context.Context, src usermem.IOSequence, q *queue, output bool) (int64, error) {
	// TODO: Use CopyInTo/safemem to avoid extra copying.
	// Get the bytes to write from user-space.
	b := make([]byte, src.NumBytes())
	n, err := src.CopyIn(ctx, b)
	if err != nil {
		return 0, err
	}
	b = b[:n]

	// If state changed, notify any waiters. If we were unable to write
	// anything, let the caller know we could block.
	if n > 0 {
		q.Notify(waiter.EventIn)
	} else {
		return 0, syserror.ErrWouldBlock
	}

	// Optionally perform line discipline transformations depending on
	// whether we're writing to the input queue or output queue.
	var buf *bytes.Buffer
	l.termiosMu.Lock()
	if output {
		buf = l.transformOutput(b)
	} else {
		buf = l.transformInput(b)
	}
	l.termiosMu.Unlock()

	// Enqueue buf at the end of the queue.
	buf.WriteTo(&q.buf)
	return int64(n), err
}

// transformOutput does ouput processing for one end of the pty. See
// drivers/tty/n_tty.c:do_output_char for an analagous kernel function.
//
// Precondition: l.termiosMu must be held.
func (l *lineDiscipline) transformOutput(buf []byte) *bytes.Buffer {
	if !l.termios.OEnabled(linux.OPOST) {
		return bytes.NewBuffer(buf)
	}

	var ret bytes.Buffer
	for len(buf) > 0 {
		c := l.removeRune(&buf)
		switch c {
		case '\n':
			if l.termios.OEnabled(linux.ONLRET) {
				l.column = 0
			}
			if l.termios.OEnabled(linux.ONLCR) {
				ret.Write([]byte{'\r', '\n'})
				continue
			}
		case '\r':
			if l.termios.OEnabled(linux.ONOCR) && l.column == 0 {
				continue
			}
			if l.termios.OEnabled(linux.OCRNL) {
				c = '\n'
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
				ret.Write(bytes.Repeat([]byte{' '}, 8))
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
		ret.WriteRune(c)
	}
	return &ret
}

// transformInput does input processing for one end of the pty. Characters
// read are transformed according to flags set in the termios struct. See
// drivers/tty/n_tty.c:n_tty_receive_char_special for an analogous kernel
// function.
//
// Precondition: l.termiosMu must be held.
func (l *lineDiscipline) transformInput(buf []byte) *bytes.Buffer {
	var ret bytes.Buffer
	for len(buf) > 0 {
		c := l.removeRune(&buf)
		switch c {
		case '\r':
			if l.termios.IEnabled(linux.IGNCR) {
				continue
			}
			if l.termios.IEnabled(linux.ICRNL) {
				c = '\n'
			}
		case '\n':
			if l.termios.IEnabled(linux.INLCR) {
				c = '\r'
			}
		}
		ret.WriteRune(c)
	}
	return &ret
}

// removeRune removes and returns the first rune from the byte array. The
// buffer's length is updated accordingly.
func (l *lineDiscipline) removeRune(b *[]byte) rune {
	var c rune
	var size int
	// If UTF-8 support is enabled, runes might be multiple bytes.
	if l.termios.IEnabled(linux.IUTF8) {
		c, size = utf8.DecodeRune(*b)
	} else {
		c = rune((*b)[0])
		size = 1
	}
	*b = (*b)[size:]
	return c
}
