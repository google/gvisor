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

package fs

import (
	"io"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/secio"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Splice moves data to this file, directly from another.
//
// Offsets are updated only if DstOffset and SrcOffset are set.
func Splice(ctx context.Context, dst *File, src *File, opts SpliceOpts) (int64, error) {
	// Check whether or not the objects being sliced are stream-oriented
	// (i.e. pipes or sockets). If yes, we elide checks and offset locks.
	srcPipe := IsPipe(src.Dirent.Inode.StableAttr) || IsSocket(src.Dirent.Inode.StableAttr)
	dstPipe := IsPipe(dst.Dirent.Inode.StableAttr) || IsSocket(dst.Dirent.Inode.StableAttr)

	if !dstPipe && !opts.DstOffset && !srcPipe && !opts.SrcOffset {
		if dst.UniqueID < src.UniqueID {
			// Acquire dst first.
			if !dst.mu.Lock(ctx) {
				return 0, syserror.ErrInterrupted
			}
			defer dst.mu.Unlock()
			if !src.mu.Lock(ctx) {
				return 0, syserror.ErrInterrupted
			}
			defer src.mu.Unlock()
		} else {
			// Acquire src first.
			if !src.mu.Lock(ctx) {
				return 0, syserror.ErrInterrupted
			}
			defer src.mu.Unlock()
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

	// Check for the limit and append-only mode.
	if !dstPipe {
		// Check for an append-only destination. Note that this will be
		// racy if an offset is provided, but it's unclear what
		// semantics are expected.  Constraints will generally be
		// enforced by a higher-level anyways.
		if err := dst.checkAppend(ctx, &opts.DstStart); err != nil {
			return 0, err
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

	// Attempt to do a write to.
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
		// Attempt as a read from.
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
		fw := &FileWriter{
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
		fr := &FileReader{
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
		n, err = io.Copy(w, r)
	}

	// Update offsets, if required.
	if n > 0 {
		if !opts.DstOffset {
			atomic.StoreInt64(&dst.offset, dst.offset+n)
		}
		if !opts.SrcOffset {
			atomic.StoreInt64(&src.offset, src.offset+n)
		}
	}

	return n, err
}
