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

package vfs2

import (
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// fileCap is the maximum allowable files for poll & select. This has no
// equivalent in Linux; it exists in gVisor since allocation failure in Go is
// unrecoverable.
const fileCap = 1024 * 1024

// Masks for "readable", "writable", and "exceptional" events as defined by
// select(2).
const (
	// selectReadEvents is analogous to the Linux kernel's
	// fs/select.c:POLLIN_SET.
	selectReadEvents = linux.POLLIN | linux.POLLHUP | linux.POLLERR

	// selectWriteEvents is analogous to the Linux kernel's
	// fs/select.c:POLLOUT_SET.
	selectWriteEvents = linux.POLLOUT | linux.POLLERR

	// selectExceptEvents is analogous to the Linux kernel's
	// fs/select.c:POLLEX_SET.
	selectExceptEvents = linux.POLLPRI
)

// pollState tracks the associated file description and waiter of a PollFD.
type pollState struct {
	file   *vfs.FileDescription
	waiter waiter.Entry
}

// initReadiness gets the current ready mask for the file represented by the FD
// stored in pfd.FD. If a channel is passed in, the waiter entry in "state" is
// used to register with the file for event notifications, and a reference to
// the file is stored in "state".
func initReadiness(t *kernel.Task, pfd *linux.PollFD, state *pollState, ch chan struct{}) {
	if pfd.FD < 0 {
		pfd.REvents = 0
		return
	}

	file := t.GetFileVFS2(pfd.FD)
	if file == nil {
		pfd.REvents = linux.POLLNVAL
		return
	}

	if ch == nil {
		defer file.DecRef(t)
	} else {
		state.file = file
		state.waiter, _ = waiter.NewChannelEntry(ch)
		file.EventRegister(&state.waiter, waiter.EventMaskFromLinux(uint32(pfd.Events)))
	}

	r := file.Readiness(waiter.EventMaskFromLinux(uint32(pfd.Events)))
	pfd.REvents = int16(r.ToLinux()) & pfd.Events
}

// releaseState releases all the pollState in "state".
func releaseState(t *kernel.Task, state []pollState) {
	for i := range state {
		if state[i].file != nil {
			state[i].file.EventUnregister(&state[i].waiter)
			state[i].file.DecRef(t)
		}
	}
}

// pollBlock polls the PollFDs in "pfd" with a bounded time specified in "timeout"
// when "timeout" is greater than zero.
//
// pollBlock returns the remaining timeout, which is always 0 on a timeout; and 0 or
// positive if interrupted by a signal.
func pollBlock(t *kernel.Task, pfd []linux.PollFD, timeout time.Duration) (time.Duration, uintptr, error) {
	var ch chan struct{}
	if timeout != 0 {
		ch = make(chan struct{}, 1)
	}

	// Register for event notification in the files involved if we may
	// block (timeout not zero). Once we find a file that has a non-zero
	// result, we stop registering for events but still go through all files
	// to get their ready masks.
	state := make([]pollState, len(pfd))
	defer releaseState(t, state)
	n := uintptr(0)
	for i := range pfd {
		initReadiness(t, &pfd[i], &state[i], ch)
		if pfd[i].REvents != 0 {
			n++
			ch = nil
		}
	}

	if timeout == 0 {
		return timeout, n, nil
	}

	haveTimeout := timeout >= 0

	for n == 0 {
		var err error
		// Wait for a notification.
		timeout, err = t.BlockWithTimeout(ch, haveTimeout, timeout)
		if err != nil {
			if err == syserror.ETIMEDOUT {
				err = nil
			}
			return timeout, 0, err
		}

		// We got notified, count how many files are ready. If none,
		// then this was a spurious notification, and we just go back
		// to sleep with the remaining timeout.
		for i := range state {
			if state[i].file == nil {
				continue
			}

			r := state[i].file.Readiness(waiter.EventMaskFromLinux(uint32(pfd[i].Events)))
			rl := int16(r.ToLinux()) & pfd[i].Events
			if rl != 0 {
				pfd[i].REvents = rl
				n++
			}
		}
	}

	return timeout, n, nil
}

// copyInPollFDs copies an array of struct pollfd unless nfds exceeds the max.
func copyInPollFDs(t *kernel.Task, addr usermem.Addr, nfds uint) ([]linux.PollFD, error) {
	if uint64(nfds) > t.ThreadGroup().Limits().GetCapped(limits.NumberOfFiles, fileCap) {
		return nil, syserror.EINVAL
	}

	pfd := make([]linux.PollFD, nfds)
	if nfds > 0 {
		if _, err := linux.CopyPollFDSliceIn(t, addr, pfd); err != nil {
			return nil, err
		}
	}

	return pfd, nil
}

func doPoll(t *kernel.Task, addr usermem.Addr, nfds uint, timeout time.Duration) (time.Duration, uintptr, error) {
	pfd, err := copyInPollFDs(t, addr, nfds)
	if err != nil {
		return timeout, 0, err
	}

	// Compatibility warning: Linux adds POLLHUP and POLLERR just before
	// polling, in fs/select.c:do_pollfd(). Since pfd is copied out after
	// polling, changing event masks here is an application-visible difference.
	// (Linux also doesn't copy out event masks at all, only revents.)
	for i := range pfd {
		pfd[i].Events |= linux.POLLHUP | linux.POLLERR
	}
	remainingTimeout, n, err := pollBlock(t, pfd, timeout)
	err = syserror.ConvertIntr(err, syserror.EINTR)

	// The poll entries are copied out regardless of whether
	// any are set or not. This aligns with the Linux behavior.
	if nfds > 0 && err == nil {
		if _, err := linux.CopyPollFDSliceOut(t, addr, pfd); err != nil {
			return remainingTimeout, 0, err
		}
	}

	return remainingTimeout, n, err
}

// CopyInFDSet copies an fd set from select(2)/pselect(2).
func CopyInFDSet(t *kernel.Task, addr usermem.Addr, nBytes, nBitsInLastPartialByte int) ([]byte, error) {
	set := make([]byte, nBytes)

	if addr != 0 {
		if _, err := t.CopyInBytes(addr, set); err != nil {
			return nil, err
		}
		// If we only use part of the last byte, mask out the extraneous bits.
		//
		// N.B. This only works on little-endian architectures.
		if nBitsInLastPartialByte != 0 {
			set[nBytes-1] &^= byte(0xff) << nBitsInLastPartialByte
		}
	}
	return set, nil
}

func doSelect(t *kernel.Task, nfds int, readFDs, writeFDs, exceptFDs usermem.Addr, timeout time.Duration) (uintptr, error) {
	if nfds < 0 || nfds > fileCap {
		return 0, syserror.EINVAL
	}

	// Calculate the size of the fd sets (one bit per fd).
	nBytes := (nfds + 7) / 8
	nBitsInLastPartialByte := nfds % 8

	// Capture all the provided input vectors.
	r, err := CopyInFDSet(t, readFDs, nBytes, nBitsInLastPartialByte)
	if err != nil {
		return 0, err
	}
	w, err := CopyInFDSet(t, writeFDs, nBytes, nBitsInLastPartialByte)
	if err != nil {
		return 0, err
	}
	e, err := CopyInFDSet(t, exceptFDs, nBytes, nBitsInLastPartialByte)
	if err != nil {
		return 0, err
	}

	// Count how many FDs are actually being requested so that we can build
	// a PollFD array.
	fdCount := 0
	for i := 0; i < nBytes; i++ {
		v := r[i] | w[i] | e[i]
		for v != 0 {
			v &= (v - 1)
			fdCount++
		}
	}

	// Build the PollFD array.
	pfd := make([]linux.PollFD, 0, fdCount)
	var fd int32
	for i := 0; i < nBytes; i++ {
		rV, wV, eV := r[i], w[i], e[i]
		v := rV | wV | eV
		m := byte(1)
		for j := 0; j < 8; j++ {
			if (v & m) != 0 {
				// Make sure the fd is valid and decrement the reference
				// immediately to ensure we don't leak. Note, another thread
				// might be about to close fd. This is racy, but that's
				// OK. Linux is racy in the same way.
				file := t.GetFileVFS2(fd)
				if file == nil {
					return 0, syserror.EBADF
				}
				file.DecRef(t)

				var mask int16
				if (rV & m) != 0 {
					mask |= selectReadEvents
				}

				if (wV & m) != 0 {
					mask |= selectWriteEvents
				}

				if (eV & m) != 0 {
					mask |= selectExceptEvents
				}

				pfd = append(pfd, linux.PollFD{
					FD:     fd,
					Events: mask,
				})
			}

			fd++
			m <<= 1
		}
	}

	// Do the syscall, then count the number of bits set.
	if _, _, err = pollBlock(t, pfd, timeout); err != nil {
		return 0, syserror.ConvertIntr(err, syserror.EINTR)
	}

	// r, w, and e are currently event mask bitsets; unset bits corresponding
	// to events that *didn't* occur.
	bitSetCount := uintptr(0)
	for idx := range pfd {
		events := pfd[idx].REvents
		i, j := pfd[idx].FD/8, uint(pfd[idx].FD%8)
		m := byte(1) << j
		if r[i]&m != 0 {
			if (events & selectReadEvents) != 0 {
				bitSetCount++
			} else {
				r[i] &^= m
			}
		}
		if w[i]&m != 0 {
			if (events & selectWriteEvents) != 0 {
				bitSetCount++
			} else {
				w[i] &^= m
			}
		}
		if e[i]&m != 0 {
			if (events & selectExceptEvents) != 0 {
				bitSetCount++
			} else {
				e[i] &^= m
			}
		}
	}

	// Copy updated vectors back.
	if readFDs != 0 {
		if _, err := t.CopyOutBytes(readFDs, r); err != nil {
			return 0, err
		}
	}

	if writeFDs != 0 {
		if _, err := t.CopyOutBytes(writeFDs, w); err != nil {
			return 0, err
		}
	}

	if exceptFDs != 0 {
		if _, err := t.CopyOutBytes(exceptFDs, e); err != nil {
			return 0, err
		}
	}

	return bitSetCount, nil
}

// timeoutRemaining returns the amount of time remaining for the specified
// timeout or 0 if it has elapsed.
//
// startNs must be from CLOCK_MONOTONIC.
func timeoutRemaining(t *kernel.Task, startNs ktime.Time, timeout time.Duration) time.Duration {
	now := t.Kernel().MonotonicClock().Now()
	remaining := timeout - now.Sub(startNs)
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

// copyOutTimespecRemaining copies the time remaining in timeout to timespecAddr.
//
// startNs must be from CLOCK_MONOTONIC.
func copyOutTimespecRemaining(t *kernel.Task, startNs ktime.Time, timeout time.Duration, timespecAddr usermem.Addr) error {
	if timeout <= 0 {
		return nil
	}
	remaining := timeoutRemaining(t, startNs, timeout)
	tsRemaining := linux.NsecToTimespec(remaining.Nanoseconds())
	_, err := tsRemaining.CopyOut(t, timespecAddr)
	return err
}

// copyOutTimevalRemaining copies the time remaining in timeout to timevalAddr.
//
// startNs must be from CLOCK_MONOTONIC.
func copyOutTimevalRemaining(t *kernel.Task, startNs ktime.Time, timeout time.Duration, timevalAddr usermem.Addr) error {
	if timeout <= 0 {
		return nil
	}
	remaining := timeoutRemaining(t, startNs, timeout)
	tvRemaining := linux.NsecToTimeval(remaining.Nanoseconds())
	_, err := tvRemaining.CopyOut(t, timevalAddr)
	return err
}

// pollRestartBlock encapsulates the state required to restart poll(2) via
// restart_syscall(2).
//
// +stateify savable
type pollRestartBlock struct {
	pfdAddr usermem.Addr
	nfds    uint
	timeout time.Duration
}

// Restart implements kernel.SyscallRestartBlock.Restart.
func (p *pollRestartBlock) Restart(t *kernel.Task) (uintptr, error) {
	return poll(t, p.pfdAddr, p.nfds, p.timeout)
}

func poll(t *kernel.Task, pfdAddr usermem.Addr, nfds uint, timeout time.Duration) (uintptr, error) {
	remainingTimeout, n, err := doPoll(t, pfdAddr, nfds, timeout)
	// On an interrupt poll(2) is restarted with the remaining timeout.
	if err == syserror.EINTR {
		t.SetSyscallRestartBlock(&pollRestartBlock{
			pfdAddr: pfdAddr,
			nfds:    nfds,
			timeout: remainingTimeout,
		})
		return 0, syserror.ERESTART_RESTARTBLOCK
	}
	return n, err
}

// Poll implements linux syscall poll(2).
func Poll(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pfdAddr := args[0].Pointer()
	nfds := uint(args[1].Uint()) // poll(2) uses unsigned long.
	timeout := time.Duration(args[2].Int()) * time.Millisecond
	n, err := poll(t, pfdAddr, nfds, timeout)
	return n, nil, err
}

// Ppoll implements linux syscall ppoll(2).
func Ppoll(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pfdAddr := args[0].Pointer()
	nfds := uint(args[1].Uint()) // poll(2) uses unsigned long.
	timespecAddr := args[2].Pointer()
	maskAddr := args[3].Pointer()
	maskSize := uint(args[4].Uint())

	timeout, err := copyTimespecInToDuration(t, timespecAddr)
	if err != nil {
		return 0, nil, err
	}

	var startNs ktime.Time
	if timeout > 0 {
		startNs = t.Kernel().MonotonicClock().Now()
	}

	if err := setTempSignalSet(t, maskAddr, maskSize); err != nil {
		return 0, nil, err
	}

	_, n, err := doPoll(t, pfdAddr, nfds, timeout)
	copyErr := copyOutTimespecRemaining(t, startNs, timeout, timespecAddr)
	// doPoll returns EINTR if interrupted, but ppoll is normally restartable
	// if interrupted by something other than a signal handled by the
	// application (i.e. returns ERESTARTNOHAND). However, if
	// copyOutTimespecRemaining failed, then the restarted ppoll would use the
	// wrong timeout, so the error should be left as EINTR.
	//
	// Note that this means that if err is nil but copyErr is not, copyErr is
	// ignored. This is consistent with Linux.
	if err == syserror.EINTR && copyErr == nil {
		err = syserror.ERESTARTNOHAND
	}
	return n, nil, err
}

// Select implements linux syscall select(2).
func Select(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	nfds := int(args[0].Int()) // select(2) uses an int.
	readFDs := args[1].Pointer()
	writeFDs := args[2].Pointer()
	exceptFDs := args[3].Pointer()
	timevalAddr := args[4].Pointer()

	// Use a negative Duration to indicate "no timeout".
	timeout := time.Duration(-1)
	if timevalAddr != 0 {
		var timeval linux.Timeval
		if _, err := timeval.CopyIn(t, timevalAddr); err != nil {
			return 0, nil, err
		}
		if timeval.Sec < 0 || timeval.Usec < 0 {
			return 0, nil, syserror.EINVAL
		}
		timeout = time.Duration(timeval.ToNsecCapped())
	}
	startNs := t.Kernel().MonotonicClock().Now()
	n, err := doSelect(t, nfds, readFDs, writeFDs, exceptFDs, timeout)
	copyErr := copyOutTimevalRemaining(t, startNs, timeout, timevalAddr)
	// See comment in Ppoll.
	if err == syserror.EINTR && copyErr == nil {
		err = syserror.ERESTARTNOHAND
	}
	return n, nil, err
}

// +marshal
type sigSetWithSize struct {
	sigsetAddr   uint64
	sizeofSigset uint64
}

// Pselect implements linux syscall pselect(2).
func Pselect(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	nfds := int(args[0].Int()) // select(2) uses an int.
	readFDs := args[1].Pointer()
	writeFDs := args[2].Pointer()
	exceptFDs := args[3].Pointer()
	timespecAddr := args[4].Pointer()
	maskWithSizeAddr := args[5].Pointer()

	timeout, err := copyTimespecInToDuration(t, timespecAddr)
	if err != nil {
		return 0, nil, err
	}

	var startNs ktime.Time
	if timeout > 0 {
		startNs = t.Kernel().MonotonicClock().Now()
	}

	if maskWithSizeAddr != 0 {
		if t.Arch().Width() != 8 {
			panic(fmt.Sprintf("unsupported sizeof(void*): %d", t.Arch().Width()))
		}
		var maskStruct sigSetWithSize
		if _, err := maskStruct.CopyIn(t, maskWithSizeAddr); err != nil {
			return 0, nil, err
		}
		if err := setTempSignalSet(t, usermem.Addr(maskStruct.sigsetAddr), uint(maskStruct.sizeofSigset)); err != nil {
			return 0, nil, err
		}
	}

	n, err := doSelect(t, nfds, readFDs, writeFDs, exceptFDs, timeout)
	copyErr := copyOutTimespecRemaining(t, startNs, timeout, timespecAddr)
	// See comment in Ppoll.
	if err == syserror.EINTR && copyErr == nil {
		err = syserror.ERESTARTNOHAND
	}
	return n, nil, err
}

// copyTimespecInToDuration copies a Timespec from the untrusted app range,
// validates it and converts it to a Duration.
//
// If the Timespec is larger than what can be represented in a Duration, the
// returned value is the maximum that Duration will allow.
//
// If timespecAddr is NULL, the returned value is negative.
func copyTimespecInToDuration(t *kernel.Task, timespecAddr usermem.Addr) (time.Duration, error) {
	// Use a negative Duration to indicate "no timeout".
	timeout := time.Duration(-1)
	if timespecAddr != 0 {
		var timespec linux.Timespec
		if _, err := timespec.CopyIn(t, timespecAddr); err != nil {
			return 0, err
		}
		if !timespec.Valid() {
			return 0, syserror.EINVAL
		}
		timeout = time.Duration(timespec.ToNsecCapped())
	}
	return timeout, nil
}

func setTempSignalSet(t *kernel.Task, maskAddr usermem.Addr, maskSize uint) error {
	if maskAddr == 0 {
		return nil
	}
	if maskSize != linux.SignalSetSize {
		return syserror.EINVAL
	}
	var mask linux.SignalSet
	if _, err := mask.CopyIn(t, maskAddr); err != nil {
		return err
	}
	mask &^= kernel.UnblockableSignals
	oldmask := t.SignalMask()
	t.SetSignalMask(mask)
	t.SetSavedSignalMask(oldmask)
	return nil
}
