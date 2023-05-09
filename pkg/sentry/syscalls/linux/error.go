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
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

var (
	partialResultOnce sync.Once
)

// incrementPartialResultMetric increments PartialResultMetric by calling
// Increment(). This is added as the func Do() which is called below requires
// us to pass a function which does not take any arguments, whereas Increment()
// takes a variadic number of arguments.
func incrementPartialResultMetric() {
	metric.WeirdnessMetric.Increment(&metric.WeirdnessTypePartialResult)
}

// HandleIOError handles special error cases for partial results. For some
// errors, we may consume the error and return only the partial read/write.
//
// op and f are used only for panics.
func HandleIOError(ctx context.Context, partialResult bool, ioerr, intr error, op string, f *vfs.FileDescription) error {
	known, err := handleIOErrorImpl(ctx, partialResult, ioerr, intr, op)
	if err != nil {
		return err
	}
	if !known {
		// An unknown error is encountered with a partial read/write.
		fs := f.Mount().Filesystem().VirtualFilesystem()
		root := vfs.RootFromContext(ctx)
		name, _ := fs.PathnameWithDeleted(ctx, root, f.VirtualDentry())
		log.Traceback("Invalid request partialResult %v and err (type %T) %v for %s operation on %q", partialResult, ioerr, ioerr, op, name)
		partialResultOnce.Do(incrementPartialResultMetric)
	}
	return nil
}

// handleIOError handles special error cases for partial results. For some
// errors, we may consume the error and return only the partial read/write.
//
// Returns false if error is unknown.
func handleIOErrorImpl(ctx context.Context, partialResult bool, errOrig, intr error, op string) (bool, error) {
	if errOrig == nil {
		// Typical successful syscall.
		return true, nil
	}

	// Translate error, if possible, to consolidate errors from other packages
	// into a smaller set of errors from linuxerr package.
	translatedErr := errOrig
	if errno, ok := linuxerr.TranslateError(errOrig); ok {
		translatedErr = errno
	}
	switch {
	case translatedErr == io.EOF:
		// EOF is always consumed. If this is a partial read/write
		// (result != 0), the application will see that, otherwise
		// they will see 0.
		return true, nil
	case linuxerr.Equals(linuxerr.EFBIG, translatedErr):
		t := kernel.TaskFromContext(ctx)
		if t == nil {
			panic("I/O error should only occur from a context associated with a Task")
		}
		// Ignore partialResult because this error only applies to
		// normal files, and for those files we cannot accumulate
		// write results.
		//
		// Do not consume the error and return it as EFBIG.
		// Simultaneously send a SIGXFSZ per setrlimit(2).
		t.SendSignal(kernel.SignalInfoNoInfo(linux.SIGXFSZ, t, t))
		return true, linuxerr.EFBIG
	case linuxerr.Equals(linuxerr.EINTR, translatedErr):
		// The syscall was interrupted. Return nil if it completed
		// partially, otherwise return the error code that the syscall
		// needs (to indicate to the kernel what it should do).
		if partialResult {
			return true, nil
		}
		return true, intr
	}

	if !partialResult {
		// Typical syscall error.
		return true, errOrig
	}

	switch {
	case linuxerr.Equals(linuxerr.EINTR, translatedErr):
		// Syscall interrupted, but completed a partial
		// read/write.  Like ErrWouldBlock, since we have a
		// partial read/write, we consume the error and return
		// the partial result.
		return true, nil
	case linuxerr.Equals(linuxerr.EFAULT, translatedErr):
		// EFAULT is only shown the user if nothing was
		// read/written. If we read something (this case), they see
		// a partial read/write. They will then presumably try again
		// with an incremented buffer, which will EFAULT with
		// result == 0.
		return true, nil
	case linuxerr.Equals(linuxerr.EPIPE, translatedErr):
		// Writes to a pipe or socket will return EPIPE if the other
		// side is gone. The partial write is returned. EPIPE will be
		// returned on the next call.
		//
		// TODO(gvisor.dev/issue/161): In some cases SIGPIPE should
		// also be sent to the application.
		return true, nil
	case linuxerr.Equals(linuxerr.ENOSPC, translatedErr):
		// Similar to EPIPE. Return what we wrote this time, and let
		// ENOSPC be returned on the next call.
		return true, nil
	case linuxerr.Equals(linuxerr.ECONNRESET, translatedErr):
		fallthrough
	case linuxerr.Equals(linuxerr.ECONNABORTED, translatedErr):
		fallthrough
	case linuxerr.Equals(linuxerr.ETIMEDOUT, translatedErr):
		// For TCP sendfile connections, we may have a reset, abort or timeout. But
		// we should just return the partial result. The next call will return the
		// error without a partial IO operation.
		return true, nil
	case linuxerr.Equals(linuxerr.EWOULDBLOCK, translatedErr):
		// Syscall would block, but completed a partial read/write.
		// This case should only be returned by IssueIO for nonblocking
		// files. Since we have a partial read/write, we consume
		// ErrWouldBlock, returning the partial result.
		return true, nil
	case linuxerr.IsRestartError(translatedErr):
		// Identical to the EINTR case.
		return true, nil
	}

	// Error is unknown and cannot be properly handled.
	return false, nil
}
