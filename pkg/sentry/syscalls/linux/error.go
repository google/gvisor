// Copyright 2018 Google LLC
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
	"io"
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/metric"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

var (
	partialResultMetric = metric.MustCreateNewUint64Metric("/syscalls/partial_result", true /* sync */, "Whether or not a partial result has occurred for this sandbox.")
	partialResultOnce   sync.Once
)

// handleIOError handles special error cases for partial results. For some
// errors, we may consume the error and return only the partial read/write.
//
// op and f are used only for panics.
func handleIOError(t *kernel.Task, partialResult bool, err, intr error, op string, f *fs.File) error {
	switch err {
	case nil:
		// Typical successful syscall.
		return nil
	case io.EOF:
		// EOF is always consumed. If this is a partial read/write
		// (result != 0), the application will see that, otherwise
		// they will see 0.
		return nil
	case syserror.ErrExceedsFileSizeLimit:
		// Ignore partialResult because this error only applies to
		// normal files, and for those files we cannot accumulate
		// write results.
		//
		// Do not consume the error and return it as EFBIG.
		// Simultaneously send a SIGXFSZ per setrlimit(2).
		t.SendSignal(kernel.SignalInfoNoInfo(linux.SIGXFSZ, t, t))
		return syscall.EFBIG
	case syserror.ErrInterrupted:
		// The syscall was interrupted. Return nil if it completed
		// partially, otherwise return the error code that the syscall
		// needs (to indicate to the kernel what it should do).
		if partialResult {
			return nil
		}
		return intr
	}

	if !partialResult {
		// Typical syscall error.
		return err
	}

	switch err {
	case syserror.EINTR:
		// Syscall interrupted, but completed a partial
		// read/write.  Like ErrWouldBlock, since we have a
		// partial read/write, we consume the error and return
		// the partial result.
		return nil
	case syserror.EFAULT:
		// EFAULT is only shown the user if nothing was
		// read/written. If we read something (this case), they see
		// a partial read/write. They will then presumably try again
		// with an incremented buffer, which will EFAULT with
		// result == 0.
		return nil
	case syserror.EPIPE:
		// Writes to a pipe or socket will return EPIPE if the other
		// side is gone. The partial write is returned. EPIPE will be
		// returned on the next call.
		//
		// TODO(gvisor.dev/issue/161): In some cases SIGPIPE should
		// also be sent to the application.
		return nil
	case syserror.ErrWouldBlock:
		// Syscall would block, but completed a partial read/write.
		// This case should only be returned by IssueIO for nonblocking
		// files. Since we have a partial read/write, we consume
		// ErrWouldBlock, returning the partial result.
		return nil
	}

	switch err.(type) {
	case kernel.SyscallRestartErrno:
		// Identical to the EINTR case.
		return nil
	}

	// An unknown error is encountered with a partial read/write.
	name, _ := f.Dirent.FullName(nil /* ignore chroot */)
	log.Traceback("Invalid request partialResult %v and err (type %T) %v for %s operation on %q, %T", partialResult, err, err, op, name, f.FileOperations)
	partialResultOnce.Do(partialResultMetric.Increment)
	return nil
}
