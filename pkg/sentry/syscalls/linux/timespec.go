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

package linux

import (
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// copyTimespecIn copies a Timespec from the untrusted app range to the kernel.
func copyTimespecIn(t *kernel.Task, addr hostarch.Addr) (linux.Timespec, error) {
	switch t.Arch().Width() {
	case 8:
		ts := linux.Timespec{}
		in := t.CopyScratchBuffer(16)
		_, err := t.CopyInBytes(addr, in)
		if err != nil {
			return ts, err
		}
		ts.Sec = int64(hostarch.ByteOrder.Uint64(in[0:]))
		ts.Nsec = int64(hostarch.ByteOrder.Uint64(in[8:]))
		return ts, nil
	default:
		return linux.Timespec{}, linuxerr.ENOSYS
	}
}

// copyTimespecOut copies a Timespec to the untrusted app range.
func copyTimespecOut(t *kernel.Task, addr hostarch.Addr, ts *linux.Timespec) error {
	switch t.Arch().Width() {
	case 8:
		out := t.CopyScratchBuffer(16)
		hostarch.ByteOrder.PutUint64(out[0:], uint64(ts.Sec))
		hostarch.ByteOrder.PutUint64(out[8:], uint64(ts.Nsec))
		_, err := t.CopyOutBytes(addr, out)
		return err
	default:
		return linuxerr.ENOSYS
	}
}

// copyTimevalIn copies a Timeval from the untrusted app range to the kernel.
func copyTimevalIn(t *kernel.Task, addr hostarch.Addr) (linux.Timeval, error) {
	switch t.Arch().Width() {
	case 8:
		tv := linux.Timeval{}
		in := t.CopyScratchBuffer(16)
		_, err := t.CopyInBytes(addr, in)
		if err != nil {
			return tv, err
		}
		tv.Sec = int64(hostarch.ByteOrder.Uint64(in[0:]))
		tv.Usec = int64(hostarch.ByteOrder.Uint64(in[8:]))
		return tv, nil
	default:
		return linux.Timeval{}, linuxerr.ENOSYS
	}
}

// copyTimevalOut copies a Timeval to the untrusted app range.
func copyTimevalOut(t *kernel.Task, addr hostarch.Addr, tv *linux.Timeval) error {
	switch t.Arch().Width() {
	case 8:
		out := t.CopyScratchBuffer(16)
		hostarch.ByteOrder.PutUint64(out[0:], uint64(tv.Sec))
		hostarch.ByteOrder.PutUint64(out[8:], uint64(tv.Usec))
		_, err := t.CopyOutBytes(addr, out)
		return err
	default:
		return linuxerr.ENOSYS
	}
}

// copyTimespecInToDuration copies a Timespec from the untrusted app range,
// validates it and converts it to a Duration.
//
// If the Timespec is larger than what can be represented in a Duration, the
// returned value is the maximum that Duration will allow.
//
// If timespecAddr is NULL, the returned value is negative.
func copyTimespecInToDuration(t *kernel.Task, timespecAddr hostarch.Addr) (time.Duration, error) {
	// Use a negative Duration to indicate "no timeout".
	timeout := time.Duration(-1)
	if timespecAddr != 0 {
		timespec, err := copyTimespecIn(t, timespecAddr)
		if err != nil {
			return 0, err
		}
		if !timespec.Valid() {
			return 0, linuxerr.EINVAL
		}
		timeout = time.Duration(timespec.ToNsecCapped())
	}
	return timeout, nil
}
