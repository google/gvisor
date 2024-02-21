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

package devpts

import (
	"bytes"
	"unicode"
	"unicode/utf8"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

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
// pseudoterminal (pty) master and replica. It can be configured to alter I/O,
// modify control characters (e.g. Ctrl-C for SIGINT), etc. The following man
// pages are good resources for how to affect the line discipline:
//
//   - termios(3)
//   - tty_ioctl(4)
//
// This file corresponds most closely to drivers/tty/n_tty.c.
//
// lineDiscipline has a simple structure but supports a multitude of options
// (see the above man pages). It consists of two queues of bytes: one from the
// terminal master to replica (the input queue) and one from replica to master
// (the output queue). When bytes are written to one end of the pty, the line
// discipline reads the bytes, modifies them or takes special action if
// required, and enqueues them to be read by the other end of the pty:
//
//	   input from terminal    +-------------+   input to process (e.g. bash)
//	+------------------------>| input queue |---------------------------+
//	|   (inputQueueWrite)     +-------------+     (inputQueueRead)      |
//	|                                                                   |
//	|                                                                   v
//
// masterFD                                                           replicaFD
//
//	^                                                                   |
//	|                                                                   |
//	|   output to terminal   +--------------+    output from process    |
//	+------------------------| output queue |<--------------------------+
//	    (outputQueueRead)    +--------------+    (outputQueueWrite)
//
// There is special handling for the ECHO option, where bytes written to the
// input queue are also output back to the terminal by being written to
// l.outQueue by the input queue transformer.
//
// Lock order:
//
//	termiosMu
//	  inQueue.mu
//	    outQueue.mu
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

	// numReplicas is the number of replica file descriptors.
	numReplicas int

	// masterWaiter is used to wait on the master end of the TTY.
	masterWaiter waiter.Queue

	// replicaWaiter is used to wait on the replica end of the TTY.
	replicaWaiter waiter.Queue

	// terminal is the terminal linked to this lineDiscipline.
	terminal *Terminal
}

func newLineDiscipline(termios linux.KernelTermios, terminal *Terminal) *lineDiscipline {
	ld := lineDiscipline{
		termios:  termios,
		terminal: terminal,
	}
	ld.inQueue.transformer = &inputQueueTransformer{}
	ld.outQueue.transformer = &outputQueueTransformer{}
	return &ld
}

// getTermios gets the linux.Termios for the tty.
func (l *lineDiscipline) getTermios(task *kernel.Task, args arch.SyscallArguments) (uintptr, error) {
	l.termiosMu.RLock()
	defer l.termiosMu.RUnlock()
	// We must copy a Termios struct, not KernelTermios.
	t := l.termios.ToTermios()
	_, err := t.CopyOut(task, args[2].Pointer())
	return 0, err
}

// setTermios sets a linux.Termios for the tty.
func (l *lineDiscipline) setTermios(task *kernel.Task, args arch.SyscallArguments) (uintptr, error) {
	l.termiosMu.Lock()
	oldCanonEnabled := l.termios.LEnabled(linux.ICANON)
	// We must copy a Termios struct, not KernelTermios.
	var t linux.Termios
	_, err := t.CopyIn(task, args[2].Pointer())
	l.termios.FromTermios(t)

	// If canonical mode is turned off, move bytes from inQueue's wait
	// buffer to its read buffer. Anything already in the read buffer is
	// now readable.
	if oldCanonEnabled && !l.termios.LEnabled(linux.ICANON) {
		l.inQueue.mu.Lock()
		l.inQueue.pushWaitBufLocked(l)
		l.inQueue.readable = len(l.inQueue.readBuf) > 0
		l.inQueue.mu.Unlock()
		l.termiosMu.Unlock()
		l.replicaWaiter.Notify(waiter.ReadableEvents)
	} else {
		l.termiosMu.Unlock()
	}

	return 0, err
}

func (l *lineDiscipline) windowSize(t *kernel.Task, args arch.SyscallArguments) error {
	l.sizeMu.Lock()
	defer l.sizeMu.Unlock()
	_, err := l.size.CopyOut(t, args[2].Pointer())
	return err
}

func (l *lineDiscipline) setWindowSize(t *kernel.Task, args arch.SyscallArguments) error {
	l.sizeMu.Lock()
	defer l.sizeMu.Unlock()
	_, err := l.size.CopyIn(t, args[2].Pointer())
	return err
}

func (l *lineDiscipline) masterReadiness() waiter.EventMask {
	// The master termios is immutable so termiosMu is not needed.
	res := l.inQueue.writeReadiness(&linux.MasterTermios) | l.outQueue.readReadiness(&linux.MasterTermios)
	l.termiosMu.RLock()
	if l.numReplicas == 0 {
		res |= waiter.EventHUp
	}
	l.termiosMu.RUnlock()
	return res
}

func (l *lineDiscipline) replicaReadiness() waiter.EventMask {
	l.termiosMu.RLock()
	defer l.termiosMu.RUnlock()
	return l.outQueue.writeReadiness(&l.termios) | l.inQueue.readReadiness(&l.termios)
}

func (l *lineDiscipline) inputQueueReadSize(t *kernel.Task, io usermem.IO, args arch.SyscallArguments) error {
	return l.inQueue.readableSize(t, io, args)
}

func (l *lineDiscipline) inputQueueRead(ctx context.Context, dst usermem.IOSequence) (int64, error) {
	l.termiosMu.RLock()
	n, pushed, notifyEcho, err := l.inQueue.read(ctx, dst, l)
	isCanon := l.termios.LEnabled(linux.ICANON)
	l.termiosMu.RUnlock()
	if err != nil {
		return 0, err
	}
	if n > 0 {
		if notifyEcho {
			l.masterWaiter.Notify(waiter.ReadableEvents | waiter.WritableEvents)
		} else {
			l.masterWaiter.Notify(waiter.WritableEvents)
		}
		if pushed {
			l.replicaWaiter.Notify(waiter.ReadableEvents)
		}
		return n, nil
	}
	if notifyEcho {
		l.masterWaiter.Notify(waiter.ReadableEvents)
	}
	if !pushed && isCanon {
		return 0, nil // EOF
	}

	return 0, linuxerr.ErrWouldBlock
}

func (l *lineDiscipline) inputQueueWrite(ctx context.Context, src usermem.IOSequence) (int64, error) {
	l.termiosMu.RLock()
	n, notifyEcho, err := l.inQueue.write(ctx, src, l)
	l.termiosMu.RUnlock()
	if err != nil {
		return 0, err
	}
	if notifyEcho {
		l.masterWaiter.Notify(waiter.ReadableEvents)
	}
	if n > 0 {
		l.replicaWaiter.Notify(waiter.ReadableEvents)
		return n, nil
	}
	return 0, linuxerr.ErrWouldBlock
}

func (l *lineDiscipline) outputQueueReadSize(t *kernel.Task, io usermem.IO, args arch.SyscallArguments) error {
	return l.outQueue.readableSize(t, io, args)
}

func (l *lineDiscipline) outputQueueRead(ctx context.Context, dst usermem.IOSequence) (int64, error) {
	l.termiosMu.RLock()
	// Ignore notifyEcho, as it cannot happen when reading from the output queue.
	n, pushed, _, err := l.outQueue.read(ctx, dst, l)
	l.termiosMu.RUnlock()
	if err != nil {
		return 0, err
	}
	if n > 0 {
		l.replicaWaiter.Notify(waiter.WritableEvents)
		if pushed {
			l.masterWaiter.Notify(waiter.ReadableEvents)
		}
		return n, nil
	}
	return 0, linuxerr.ErrWouldBlock
}

func (l *lineDiscipline) outputQueueWrite(ctx context.Context, src usermem.IOSequence) (int64, error) {
	l.termiosMu.RLock()
	// Ignore notifyEcho, as it cannot happen when writing to the output queue.
	n, _, err := l.outQueue.write(ctx, src, l)
	l.termiosMu.RUnlock()
	if err != nil {
		return 0, err
	}
	l.masterWaiter.Notify(waiter.ReadableEvents)
	return n, nil
}

// replicaOpen is called when a replica file descriptor is opened.
func (l *lineDiscipline) replicaOpen() {
	l.termiosMu.Lock()
	defer l.termiosMu.Unlock()
	l.numReplicas++
}

// replicaClose is called when a replica file descriptor is closed.
func (l *lineDiscipline) replicaClose() {
	l.termiosMu.Lock()
	l.numReplicas--
	notify := l.numReplicas == 0
	l.termiosMu.Unlock()
	if notify {
		l.masterWaiter.Notify(waiter.EventHUp)
	}
}

// transformer is a helper interface to make it easier to stateify queue.
type transformer interface {
	// transform functions require queue's mutex to be held.
	// The boolean indicates whether there was any echoed bytes.
	transform(*lineDiscipline, *queue, []byte) (int, bool)
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
//   - l.termiosMu must be held for reading.
//   - q.mu must be held.
func (*outputQueueTransformer) transform(l *lineDiscipline, q *queue, buf []byte) (int, bool) {
	// transformOutput is effectively always in noncanonical mode, as the
	// master termios never has ICANON set.
	sizeBudget := nonCanonMaxBytes - len(q.readBuf)
	if sizeBudget <= 0 {
		return 0, false
	}

	if !l.termios.OEnabled(linux.OPOST) {
		copySize := min(len(buf), sizeBudget)
		q.readBuf = append(q.readBuf, buf[:copySize]...)
		if len(q.readBuf) > 0 {
			q.readable = true
		}
		return copySize, false
	}

	var ret int

Outer:
	for ; len(buf) > 0 && sizeBudget > 0; sizeBudget = nonCanonMaxBytes - len(q.readBuf) {
		size := l.peek(buf)
		if size > sizeBudget {
			break Outer
		}
		cBytes := append([]byte{}, buf[:size]...)
		buf = buf[size:]
		// We're guaranteed that cBytes has at least one element.
	cByteSwitch:
		switch cBytes[0] {
		case '\n':
			if l.termios.OEnabled(linux.ONLRET) {
				l.column = 0
			}
			if l.termios.OEnabled(linux.ONLCR) {
				if sizeBudget < 2 {
					break Outer
				}
				ret += size
				q.readBuf = append(q.readBuf, '\r', '\n')
				continue Outer
			}
		case '\r':
			if l.termios.OEnabled(linux.ONOCR) && l.column == 0 {
				// Treat the carriage return as processed, since it's a no-op.
				ret += size
				continue Outer
			}
			if l.termios.OEnabled(linux.OCRNL) {
				cBytes[0] = '\n'
				if l.termios.OEnabled(linux.ONLRET) {
					l.column = 0
				}
				break cByteSwitch
			}
			l.column = 0
		case '\t':
			spaces := spacesPerTab - l.column%spacesPerTab
			if l.termios.OutputFlags&linux.TABDLY == linux.XTABS {
				if sizeBudget < spacesPerTab {
					break Outer
				}
				ret += size
				l.column += spaces
				q.readBuf = append(q.readBuf, bytes.Repeat([]byte{' '}, spacesPerTab)...)
				continue Outer
			}
			l.column += spaces
		case '\b':
			if l.column > 0 {
				l.column--
			}
		default:
			l.column++
		}
		ret += size
		q.readBuf = append(q.readBuf, cBytes...)
	}
	if len(q.readBuf) > 0 {
		q.readable = true
	}
	return ret, false
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
// It returns an extra boolean indicating whether any characters need to be
// echoed, in which case we need to notify readers.
//
// Preconditions:
//   - l.termiosMu must be held for reading.
//   - q.mu must be held.
func (*inputQueueTransformer) transform(l *lineDiscipline, q *queue, buf []byte) (int, bool) {
	// If there's a line waiting to be read in canonical mode, don't write
	// anything else to the read buffer.
	if l.termios.LEnabled(linux.ICANON) && q.readable {
		return 0, false
	}

	maxBytes := nonCanonMaxBytes
	if l.termios.LEnabled(linux.ICANON) {
		maxBytes = canonMaxBytes
	}

	var ret int
	var notifyEcho bool
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
		case l.termios.ControlCharacters[linux.VINTR]: // ctrl-c
			// The input queue is reading from the master TTY and
			// writing to the replica TTY which is connected to the
			// interactive program (like bash). We want to send the
			// signal the process connected to the replica TTY.
			l.terminal.replicaKTTY.SignalForegroundProcessGroup(kernel.SignalInfoPriv(linux.SIGINT))
		case l.termios.ControlCharacters[linux.VSUSP]: // ctrl-z
			l.terminal.replicaKTTY.SignalForegroundProcessGroup(kernel.SignalInfoPriv(linux.SIGTSTP))
		case l.termios.ControlCharacters[linux.VQUIT]: // ctrl-\
			l.terminal.replicaKTTY.SignalForegroundProcessGroup(kernel.SignalInfoPriv(linux.SIGQUIT))

		// In canonical mode, some characters need to be handled specially; for example, backspace.
		// This roughly aligns with n_tty.c:n_tty_receive_char_canon and n_tty.c:eraser
		// cBytes[0] == ControlCharacters[linux.VKILL] is also handled by n_tty.c:eraser, but this isn't implemented
		case l.termios.ControlCharacters[linux.VWERASE]:
			if !l.termios.LEnabled(linux.IEXTEN) {
				break
			}
			fallthrough
		case l.termios.ControlCharacters[linux.VERASE]:
			if !l.termios.LEnabled(linux.ICANON) {
				break
			}

			c := cBytes[0]
			killType := linux.VERASE
			if c == l.termios.ControlCharacters[linux.VWERASE] {
				killType = linux.VWERASE
			}
			seenAlphanumeric := false
			for len(q.readBuf) > 0 {
				// Erase a character. If IUTF8 is enabled, erase an entire multibyte unicode character.
				var toErase byte
				cnt := 0
				isContinuationByte := true
				for ; cnt < len(q.readBuf) && isContinuationByte; cnt++ {
					toErase = q.readBuf[len(q.readBuf)-cnt-1]
					isContinuationByte = l.termios.IEnabled(linux.IUTF8) && (toErase&0xc0) == 0x80
				}
				if isContinuationByte {
					// Do not partially erase a multibyte unicode character.
					break
				}

				// VWERASE will continue erasing characters until we encounter the first non-alphanumeric character
				// that follows some alphanumeric character. We consider "_" to be alphanumeric.
				if killType == linux.VWERASE {
					if unicode.IsLetter(rune(toErase)) || unicode.IsDigit(rune(toErase)) || toErase == '_' {
						seenAlphanumeric = true
					} else if seenAlphanumeric {
						break
					}
				}

				q.readBuf = q.readBuf[:len(q.readBuf)-cnt]
				if l.termios.LEnabled(linux.ECHO) {
					if l.termios.LEnabled(linux.ECHOPRT) {
						// Not implemented
					} else if killType == linux.VERASE && !l.termios.LEnabled(linux.ECHOE) {
						// Not implemented
					} else if toErase == '\t' {
						// Not implemented
					} else {
						const unicodeDelete byte = 0x7f
						isCtrl := toErase < 0x20 || toErase == unicodeDelete
						echoctl := l.termios.LEnabled(linux.ECHOCTL)

						charsToDelete := 1
						if isCtrl {
							// echoctl controls how we echo control characters, which also determines how we delete them.
							if echoctl {
								// echoctl echoes control characters as ^X, so we need to erase two characters.
								charsToDelete = 2
							} else {
								// if echoctl is disabled, we don't echo control characters so we don't have to erase anything.
								charsToDelete = 0
							}
						}
						for i := 0; i < charsToDelete; i++ {
							// Linux's kernel does character deletion with this sequence
							// of bytes, presumably because some older terminals don't erase
							// characters with \b, so we need to "erase" the old character
							// by writing a space over it.
							l.outQueue.writeBytes([]byte{'\b', ' ', '\b'}, l)
						}
					}
				}

				// VERASE only erases a single character
				if killType == linux.VERASE {
					break
				}
			}

			buf = buf[1:]
			ret += 1
			notifyEcho = true
			continue
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
			notifyEcho = true
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

	return ret, notifyEcho
}

// shouldDiscard returns whether c should be discarded. In canonical mode, if
// too many bytes are enqueued, we keep reading input and discarding it until
// we find a terminating character. Signal/echo processing still occurs.
//
// Precondition:
//   - l.termiosMu must be held for reading.
//   - q.mu must be held.
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
