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

	"gvisor.dev/gvisor/pkg/secio"
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
	// (i.e. pipes or sockets). If yes, we elide checks and offset locks.
	srcPipe := IsPipe(src.Dirent.Inode.StableAttr) || IsSocket(src.Dirent.Inode.StableAttr)
	dstPipe := IsPipe(dst.Dirent.Inode.StableAttr) || IsSocket(dst.Dirent.Inode.StableAttr)

	if !dstPipe && !opts.DstOffset && !srcPipe && !opts.SrcOffset {
		switch {
		case dst.UniqueID < src.UniqueID:
			// Acquire dst first.
			if !dst.mu.Lock(ctx) {
				return 0, syserror.ErrInterrupted
			}
			defer dst.mu.Unlock()
			if !src.mu.Lock(ctx) {
				return 0, syserror.ErrInterrupted
			}
			defer src.mu.Unlock()
		case dst.UniqueID > src.UniqueID:
			// Acquire src first.
			if !src.mu.Lock(ctx) {
				return 0, syserror.ErrInterrupted
			}
			defer src.mu.Unlock()
			if !dst.mu.Lock(ctx) {
				return 0, syserror.ErrInterrupted
			}
			defer dst.mu.Unlock()
		case dst.UniqueID == src.UniqueID:
			// Acquire only one lock; it's the same file. This is a
			// bit of a edge case, but presumably it's possible.
			if !dst.mu.Lock(ctx) {
				return 0, syserror.ErrInterrupted
			}
			defer dst.mu.Unlock()
		}
		// Use both offsets (locked).
		opts.DstStart = dst.offset
		opts.SrcStart = src.offset
	} else if !dstPipe && !opts.DstOffset {
		// Acquire only dst.
		if !dst.mu.Lock(ctx) {
			return 0, syserror.ErrInterrupted
		}
		defer dst.mu.Unlock()
		opts.DstStart = dst.offset // Safe: locked.
	} else if !srcPipe && !opts.SrcOffset {
		// Acquire only src.
		if !src.mu.Lock(ctx) {
			return 0, syserror.ErrInterrupted
		}
		defer src.mu.Unlock()
		opts.SrcStart = src.offset // Safe: locked.
	}

	// Check append-only mode and the limit.
	if !dstPipe {
		unlock := dst.Dirent.Inode.lockAppendMu(dst.Flags().Append)
		defer unlock()
		if dst.Flags().Append {
			if opts.DstOffset {
				// We need to acquire the lock.
				if !dst.mu.Lock(ctx) {
					return 0, syserror.ErrInterrupted
				}
				defer dst.mu.Unlock()
			}
			// Figure out the appropriate offset to use.
			if err := dst.offsetForAppend(ctx, &opts.DstStart); err != nil {
				return 0, err
			}
		}

		// Enforce file limits.
		limit, ok := dst.checkLimit(ctx, opts.DstStart)
		switch {
		case ok && limit == 0:
			return 0, syserror.ErrExceedsFileSizeLimit
		case ok && limit < opts.Length:
			opts.Length = limit // Cap the write.
		}
	}

	// Attempt to do a WriteTo; this is likely the most efficient.
	//
	// The underlying implementation may be able to donate buffers.
	newOpts := SpliceOpts{
		Length:    opts.Length,
		SrcStart:  opts.SrcStart,
		SrcOffset: !srcPipe,
		Dup:       opts.Dup,
		DstStart:  opts.DstStart,
		DstOffset: !dstPipe,
	}
	n, err := src.FileOperations.WriteTo(ctx, src, dst, newOpts)
	if n == 0 && err != nil {
		// Attempt as a ReadFrom. If a WriteTo, a ReadFrom may also
		// be more efficient than a copy if buffers are cached or readily
		// available. (It's unlikely that they can actually be donate
		n, err = dst.FileOperations.ReadFrom(ctx, dst, src, newOpts)
	}
	if n == 0 && err != nil {
		// If we've failed up to here, and at least one of the sources
		// is a pipe or socket, then we can't properly support dup.
		// Return an error indicating that this operation is not
		// supported.
		if (srcPipe || dstPipe) && newOpts.Dup {
			return 0, syserror.EINVAL
		}

		// We failed to splice the files. But that's fine; we just fall
		// back to a slow path in this case. This copies without doing
		// any mode changes, so should still be more efficient.
		var (
			r io.Reader
			w io.Writer
		)
		fw := &lockedWriter{
			Ctx:  ctx,
			File: dst,
		}
		if newOpts.DstOffset {
			// Use the provided offset.
			w = secio.NewOffsetWriter(fw, newOpts.DstStart)
		} else {
			// Writes will proceed with no offset.
			w = fw
		}
		fr := &lockedReader{
			Ctx:  ctx,
			File: src,
		}
		if newOpts.SrcOffset {
			// Limit to the given offset and length.
			r = io.NewSectionReader(fr, opts.SrcStart, opts.Length)
		} else {
			// Limit just to the given length.
			r = &io.LimitedReader{fr, opts.Length}
		}

		// Copy between the two.
		//
		// FIXME(gvisor.dev/issue/565): This will lose data if the write fails.
		n, err = io.Copy(w, r)
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

	return n, err
}
