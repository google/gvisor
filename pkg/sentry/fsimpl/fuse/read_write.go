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

package fuse

import (
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/usermem"
)

// ReadInPages sends FUSE_READ requests for the size after round it up to
// a multiple of page size, blocks on it for reply, processes the reply
// and returns the payload (or joined payloads) as a byte slice.
// This is used for the general purpose reading.
// We do not support direct IO (which read the exact number of bytes)
// at this moment.
func (fs *filesystem) ReadInPages(ctx context.Context, fd *regularFileFD, off uint64, size uint32) ([][]byte, uint32, error) {
	attributeVersion := fs.conn.attributeVersion.Load()

	// Round up to a multiple of page size.
	readSize, _ := hostarch.PageRoundUp(uint64(size))

	// One request cannot exceed either maxRead or maxPages.
	maxPages := fs.conn.maxRead >> hostarch.PageShift
	if maxPages > uint32(fs.conn.maxPages) {
		maxPages = uint32(fs.conn.maxPages)
	}

	var outs [][]byte
	var sizeRead uint32

	// readSize is a multiple of hostarch.PageSize.
	// Always request bytes as a multiple of pages.
	pagesRead, pagesToRead := uint32(0), uint32(readSize>>hostarch.PageShift)

	// Reuse the same struct for unmarshalling to avoid unnecessary memory allocation.
	in := linux.FUSEReadIn{
		Fh:        fd.Fh,
		LockOwner: 0, // TODO(gvisor.dev/issue/3245): file lock
		ReadFlags: 0, // TODO(gvisor.dev/issue/3245): |= linux.FUSE_READ_LOCKOWNER
		Flags:     fd.statusFlags(),
	}

	// This loop is intended for fragmented read where the bytes to read is
	// larger than either the maxPages or maxRead.
	// For the majority of reads with normal size, this loop should only
	// execute once.
	for pagesRead < pagesToRead {
		pagesCanRead := pagesToRead - pagesRead
		if pagesCanRead > maxPages {
			pagesCanRead = maxPages
		}

		in.Offset = off + (uint64(pagesRead) << hostarch.PageShift)
		in.Size = pagesCanRead << hostarch.PageShift

		// TODO(gvisor.dev/issue/3247): support async read.
		req := fs.conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), fd.inode().nodeID, linux.FUSE_READ, &in)
		res, err := fs.conn.Call(ctx, req)
		if err != nil {
			return nil, 0, err
		}
		if err := res.Error(); err != nil {
			return nil, 0, err
		}

		// Not enough bytes in response,
		// either we reached EOF,
		// or the FUSE server sends back a response
		// that cannot even fit the hdr.
		if len(res.data) <= res.hdr.SizeBytes() {
			// We treat both case as EOF here for now
			// since there is no reliable way to detect
			// the over-short hdr case.
			break
		}

		// Directly using the slice to avoid extra copy.
		out := res.data[res.hdr.SizeBytes():]

		outs = append(outs, out)
		sizeRead += uint32(len(out))

		pagesRead += pagesCanRead
	}

	defer fs.ReadCallback(ctx, fd.inode(), off, size, sizeRead, attributeVersion) // +checklocksforce: fd.inode() locks are held during fd operations.

	// No bytes returned: offset >= EOF.
	if len(outs) == 0 {
		return nil, 0, io.EOF
	}

	return outs, sizeRead, nil
}

// ReadCallback updates several information after receiving a read response.
// Due to readahead, sizeRead can be larger than size.
//
// +checklocks:i.attrMu
func (fs *filesystem) ReadCallback(ctx context.Context, i *inode, off uint64, size uint32, sizeRead uint32, attributeVersion uint64) {
	// TODO(gvisor.dev/issue/3247): support async read.
	// If this is called by an async read, correctly process it.
	// May need to update the signature.
	i.touchAtime()
	// Reached EOF.
	if sizeRead < size {
		// TODO(gvisor.dev/issue/3630): If we have writeback cache, then we need to fill this hole.
		// Might need to update the buf to be returned from the Read().

		// Update existing size.
		newSize := off + uint64(sizeRead)
		fs.conn.mu.Lock()
		if attributeVersion == i.attrVersion.Load() && newSize < i.size.Load() {
			i.attrVersion.Store(i.fs.conn.attributeVersion.Add(1))
			i.size.Store(newSize)
		}
		fs.conn.mu.Unlock()
	}
}

// Write sends FUSE_WRITE requests and return the bytes written according to the
// response.
func (fs *filesystem) Write(ctx context.Context, fd *regularFileFD, offset int64, src usermem.IOSequence) (int64, int64, error) {
	// One request cannot exceed either maxWrite or maxPages.
	maxWrite := uint32(fs.conn.maxPages) << hostarch.PageShift
	if maxWrite > fs.conn.maxWrite {
		maxWrite = fs.conn.maxWrite
	}

	// Reuse the same struct for unmarshalling to avoid unnecessary memory allocation.
	in := linux.FUSEWritePayloadIn{
		Header: linux.FUSEWriteIn{
			Fh: fd.Fh,
			// TODO(gvisor.dev/issue/3245): file lock
			LockOwner: 0,
			// TODO(gvisor.dev/issue/3245): |= linux.FUSE_READ_LOCKOWNER
			// TODO(gvisor.dev/issue/3237): |= linux.FUSE_WRITE_CACHE (not added yet)
			WriteFlags: 0,
			Flags:      fd.statusFlags(),
		},
	}

	// This loop is intended for fragmented write where the bytes to write is
	// larger than either the maxWrite or maxPages or when bigWrites is false.
	// Unless a small value for max_write is explicitly used, this loop
	// is expected to execute only once for the majority of the writes.
	n := int64(0)
	end := offset + src.NumBytes()
	for n < end {
		writeSize := uint32(end - n)

		// Limit the write size to one page.
		// Note that the bigWrites flag is obsolete,
		// latest libfuse always sets it on.
		if !fs.conn.bigWrites && writeSize > hostarch.PageSize {
			writeSize = hostarch.PageSize
		}
		// Limit the write size to maxWrite.
		if writeSize > maxWrite {
			writeSize = maxWrite
		}

		// TODO(gvisor.dev/issue/3237): Add cache support:
		// buffer cache. Ideally we write from src to our buffer cache first.
		// The slice passed to fs.Write() should be a slice from buffer cache.
		data := make([]byte, writeSize)
		cp, _ := src.CopyIn(ctx, data)
		data = data[:cp]

		in.Header.Offset = uint64(offset)
		in.Header.Size = uint32(cp)
		in.Payload = data

		req := fs.conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), fd.inode().nodeID, linux.FUSE_WRITE, &in)
		// TODO(gvisor.dev/issue/3247): support async write.
		res, err := fs.conn.Call(ctx, req)
		if err != nil {
			return n, offset, err
		}
		out := linux.FUSEWriteOut{}
		if err := res.UnmarshalPayload(&out); err != nil {
			return n, offset, err
		}
		n += int64(out.Size)
		offset += int64(out.Size)
		src = src.DropFirst64(int64(out.Size))

		if err := res.Error(); err != nil {
			return n, offset, err
		}
		// Write more than requested? EIO.
		if out.Size > writeSize {
			return n, offset, linuxerr.EIO
		}
		// Break if short write. Not necessarily an error.
		if out.Size != writeSize {
			break
		}
	}
	return n, offset, nil
}
