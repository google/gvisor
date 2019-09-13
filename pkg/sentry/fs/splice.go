// Copyright 2019 The gVisor Authors.
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

package fs

import (
	"io"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Splice moves data to this file, directly from another.
//
// Offsets are updated only if DstOffset and SrcOffset are set.
func Splice(ctx context.Context, dst *File, src *File, opts SpliceOpts) (int64, error) {
	// Verify basic file flag permissions.
	if !dst.Flags().Write || !src.Flags().Read {
		return 0, syserror.EBADF
	}

	// Check whether or not the objects being sliced are stream-oriented
	// (i.e. pipes or sockets). For all stream-oriented files and files
	// where a specific offiset is not request, we acquire the file mutex.
	// This has two important side effects. First, it provides the standard
	// protection against concurrent writes that would mutate the offset.
	// Second, it prevents Splice deadlocks. Only internal anonymous files
	// implement the ReadFrom and WriteTo methods directly, and since such
	// anonymous files are referred to by a unique fs.File object, we know
	// that the file mutex takes strict precedence over internal locks.
	// Since we enforce lock ordering here, we can't deadlock by using
	// using a file in two different splice operations simultaneously.
	srcPipe := !IsRegular(src.Dirent.Inode.StableAttr)
	dstPipe := !IsRegular(dst.Dirent.Inode.StableAttr)
	dstAppend := !dstPipe && dst.Flags().Append
	srcLock := srcPipe || !opts.SrcOffset
	dstLock := dstPipe || !opts.DstOffset || dstAppend

	switch {
	case srcLock && dstLock:
		switch {
		case dst.UniqueID < src.UniqueID:
			// Acquire dst first.
			if !dst.mu.Lock(ctx) {
				return 0, syserror.ErrInterrupted
			}
			if !src.mu.Lock(ctx) {
				dst.mu.Unlock()
				return 0, syserror.ErrInterrupted
			}
		case dst.UniqueID > src.UniqueID:
			// Acquire src first.
			if !src.mu.Lock(ctx) {
				return 0, syserror.ErrInterrupted
			}
			if !dst.mu.Lock(ctx) {
				src.mu.Unlock()
				return 0, syserror.ErrInterrupted
			}
		case dst.UniqueID == src.UniqueID:
			// Acquire only one lock; it's the same file. This is a
			// bit of a edge case, but presumably it's possible.
			if !dst.mu.Lock(ctx) {
				return 0, syserror.ErrInterrupted
			}
			srcLock = false // Only need one unlock.
		}
		// Use both offsets (locked).
		opts.DstStart = dst.offset
		opts.SrcStart = src.offset
	case dstLock:
		// Acquire only dst.
		if !dst.mu.Lock(ctx) {
			return 0, syserror.ErrInterrupted
		}
		opts.DstStart = dst.offset // Safe: locked.
	case srcLock:
		// Acquire only src.
		if !src.mu.Lock(ctx) {
			return 0, syserror.ErrInterrupted
		}
		opts.SrcStart = src.offset // Safe: locked.
	}

	var err error
	if dstAppend {
		unlock := dst.Dirent.Inode.lockAppendMu(dst.Flags().Append)
		defer unlock()

		// Figure out the appropriate offset to use.
		err = dst.offsetForAppend(ctx, &opts.DstStart)
	}
	if err == nil && !dstPipe {
		// Enforce file limits.
		limit, ok := dst.checkLimit(ctx, opts.DstStart)
		switch {
		case ok && limit == 0:
			err = syserror.ErrExceedsFileSizeLimit
		case ok && limit < opts.Length:
			opts.Length = limit // Cap the write.
		}
	}
	if err != nil {
		if dstLock {
			dst.mu.Unlock()
		}
		if srcLock {
			src.mu.Unlock()
		}
		return 0, err
	}

	// Construct readers and writers for the splice. This is used to
	// provide a safer locking path for the WriteTo/ReadFrom operations
	// (since they will otherwise go through public interface methods which
	// conflict with locking done above), and simplifies the fallback path.
	w := &lockedWriter{
		Ctx:    ctx,
		File:   dst,
		Offset: opts.DstStart,
	}
	r := &lockedReader{
		Ctx:    ctx,
		File:   src,
		Offset: opts.SrcStart,
	}

	// Attempt to do a WriteTo; this is likely the most efficient.
	n, err := src.FileOperations.WriteTo(ctx, src, w, opts.Length, opts.Dup)
	if n == 0 && err != nil && err != syserror.ErrWouldBlock && !opts.Dup {
		// Attempt as a ReadFrom. If a WriteTo, a ReadFrom may also be
		// more efficient than a copy if buffers are cached or readily
		// available. (It's unlikely that they can actually be donated).
		n, err = dst.FileOperations.ReadFrom(ctx, dst, r, opts.Length)
	}

	// Support one last fallback option, but only if at least one of
	// the source and destination are regular files. This is because
	// if we block at some point, we could lose data. If the source is
	// not a pipe then reading is not destructive; if the destination
	// is a regular file, then it is guaranteed not to block writing.
	if n == 0 && err != nil && err != syserror.ErrWouldBlock && !opts.Dup && (!dstPipe || !srcPipe) {
		// Fallback to an in-kernel copy.
		n, err = io.Copy(w, &io.LimitedReader{
			R: r,
			N: opts.Length,
		})
	}

	// Update offsets, if required.
	if n > 0 {
		if !dstPipe && !opts.DstOffset {
			atomic.StoreInt64(&dst.offset, dst.offset+n)
		}
		if !srcPipe && !opts.SrcOffset {
			atomic.StoreInt64(&src.offset, src.offset+n)
		}
	}

	// Drop locks.
	if dstLock {
		dst.mu.Unlock()
	}
	if srcLock {
		src.mu.Unlock()
	}

	return n, err
}
