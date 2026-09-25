// Copyright 2023 The gVisor Authors.
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

package compressio

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
)

// nocompressio provides data storage that does not use data compression but
// offers optional data integrity via SHA-256 hashing.
//
// When using data integrity option, the stream format is defined as follows:
//
// /------------------------------------------------------\
// |                  data size (4-bytes)                 |
// +------------------------------------------------------+
// |                  data                                |
// +------------------------------------------------------+
// |       (optional) hash (32-bytes)                     |
// +------------------------------------------------------+
// |                  data size (4-bytes)                 |
// +------------------------------------------------------+
// |                       ......                         |
// \------------------------------------------------------/
//
// where each hash is calculated from the following items in order
//
//	data
//	data size
//  previous hash

// maxVerifiedChunkSize is the maximum size of a chunk that SimpleReader holds
// in memory. SimpleReader compares the hash of such a chunk before it gives the
// data to the caller. SimpleReader gives a larger chunk to the caller first,
// then compares the hash at the end of the chunk.
const maxVerifiedChunkSize = 1 << 20 // 1 MiB

// ErrUnverifiedData shows that the reader gave data that no hash covers.
var ErrUnverifiedData = errors.New("stream contains unverified data")

// ErrTrailingData shows that the stream does not end where the caller stopped.
var ErrTrailingData = errors.New("unexpected trailing data in stream")

// SimpleReader is a reader for uncompressed image containing hashes.
//
// With a key, SimpleReader never gives data together with an error. The first
// error stops the reader, and all subsequent reads give that error. Callers
// that use the data must also call Verify when they stop reading.
type SimpleReader struct {
	// source is the underlying stream.
	source io.ReadCloser

	// bin is a bufio reader for the underlying stream.
	bin *bufio.Reader

	// h is the hash object.
	h hash.Hash

	// current data chunk size
	chunkSize uint32

	// streamLeft is the number of bytes of the current chunk that the reader
	// did not read yet. It is zero unless a chunk is too large to hold.
	streamLeft uint32

	// unverified is true if the reader gave data from the current chunk, but
	// did not compare the hash of the chunk yet.
	unverified bool

	// pending is data that a hash covers. The reader did not give it to the
	// caller yet. It always aliases store.
	pending []byte

	// store is the backing array for pending. Its size is not more than
	// maxVerifiedChunkSize.
	store []byte

	// err is the first error. All subsequent reads give this error.
	err error

	// prevHash is the previous hash value.
	prevHash [sha256.Size]byte

	// scratch is a scratch buffer used for reading chunk size and hash values.
	scratch [sha256.Size]byte
}

var _ io.Reader = (*SimpleReader)(nil)

const (
	defaultBufSize = 256 * 1024
)

// NewSimpleReader returns a new (uncompressed) reader. If key is non-nil, the
// data stream is assumed to contain expected hash values. See package comments
// for details.
func NewSimpleReader(in io.ReadCloser, key []byte) *SimpleReader {
	bin := bufio.NewReaderSize(in, defaultBufSize)
	r := &SimpleReader{
		source: in,
		bin:    bin,
	}
	if len(key) > 0 {
		r.h = hmac.New(sha256.New, key)
	}
	return r
}

// fail keeps err. This read and all subsequent reads give err and no data.
func (r *SimpleReader) fail(err error) (int, error) {
	if r.err == nil {
		r.err = err
	}
	return 0, r.err
}

// Read implements io.Reader.Read.
func (r *SimpleReader) Read(p []byte) (int, error) {
	if r.h == nil {
		// Since there is no key, this image doesn't use the data integrity
		// stream format mentioned in package comments. We can just use the
		// bufio reader.
		return r.bin.Read(p)
	}
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	// Give the data that the reader holds.
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}

	if r.streamLeft == 0 {
		// Start the next chunk.
		if err := r.nextChunk(); err != nil {
			return r.fail(err)
		}
		if len(r.pending) > 0 {
			n := copy(p, r.pending)
			r.pending = r.pending[n:]
			return n, nil
		}
	}

	// The chunk is too large to hold. Read it directly.
	toRead := uint32(len(p))
	if toRead > r.streamLeft {
		toRead = r.streamLeft
	}
	n, err := r.bin.Read(p[:toRead])
	if n > 0 {
		_, _ = r.h.Write(p[:n])
		r.streamLeft -= uint32(n)
		r.unverified = true
	}
	if r.streamLeft == 0 {
		if verifyErr := r.verifyChunk(); verifyErr != nil {
			// The hashes do not agree. Give no data from this chunk.
			return r.fail(verifyErr)
		}
		r.unverified = false
		return n, nil
	}
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		if n > 0 {
			// Give the data now. The next read gives the error.
			r.err = err
			return n, nil
		}
		return r.fail(err)
	}
	return n, nil
}

// nextChunk reads the header of the next chunk. For a small chunk, nextChunk
// also reads the data and compares the hash. Read gets the data of a large
// chunk directly from the stream.
func (r *SimpleReader) nextChunk() error {
	if _, err := io.ReadFull(r.bin, r.scratch[:4]); err != nil {
		// io.EOF shows that the stream ends on a chunk boundary.
		return err
	}
	chunkSize := binary.BigEndian.Uint32(r.scratch[:4])
	if chunkSize == 0 {
		// this must not happen
		return io.ErrNoProgress
	}
	r.chunkSize = chunkSize
	r.h.Reset()

	if chunkSize > maxVerifiedChunkSize {
		r.streamLeft = chunkSize
		return nil
	}

	if uint32(cap(r.store)) < chunkSize {
		r.store = make([]byte, chunkSize)
	}
	b := r.store[:chunkSize]
	if _, err := io.ReadFull(r.bin, b); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	_, _ = r.h.Write(b)
	if err := r.verifyChunk(); err != nil {
		return err
	}
	r.pending = b
	return nil
}

// verifyChunk compares the hash of the current chunk with the hash in the
// stream.
//
// Precondition: r.h contains all of the data of the chunk.
func (r *SimpleReader) verifyChunk() error {
	// Add data size to hash.
	binary.BigEndian.PutUint32(r.scratch[:4], r.chunkSize)
	_, _ = r.h.Write(r.scratch[:4])

	// Add previous hash to hash.
	_, _ = r.h.Write(r.prevHash[:])

	// Compute the hash into prevHash, now that we don't need the old value.
	// Pass a 32-byte capacity slice (with 0 length) to avoid allocation.
	r.h.Sum(r.prevHash[0:0:sha256.Size])

	// Read the hash value from the stream.
	if _, err := io.ReadFull(r.bin, r.scratch[:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	if !hmac.Equal(r.scratch[:sha256.Size], r.prevHash[:sha256.Size]) {
		return ErrHashMismatch
	}
	r.chunkSize = 0
	return nil
}

// Verify gives an error if a hash does not cover all of the data that Read
// gave, or if the stream does not end where the caller stopped. Callers that
// use the data must call Verify when they stop reading.
//
// Verify does nothing if the reader has no key.
func (r *SimpleReader) Verify() error {
	if r.h == nil {
		return nil
	}
	if r.err != nil && r.err != io.EOF {
		return r.err
	}
	if r.unverified || r.streamLeft != 0 {
		return ErrUnverifiedData
	}
	if len(r.pending) != 0 {
		return ErrTrailingData
	}
	if r.err == io.EOF {
		// The reader read all of the stream, and all hashes agree.
		return nil
	}
	// The caller stopped on a chunk boundary. Make sure that the stream ends
	// here.
	var b [1]byte
	n, err := r.Read(b[:])
	if n != 0 {
		return ErrTrailingData
	}
	if err != io.EOF {
		return err
	}
	return nil
}

// Close implements io.Closer.Close.
func (r *SimpleReader) Close() error {
	return r.source.Close()
}

// SimpleWriter is a writer that does not compress.
type SimpleWriter struct {
	// base is the underlying writer.
	base io.Writer

	// bufOut is a buffered writer. If nil, SimpleWriter does buffering manually.
	bufOut *bufio.Writer

	// h is the hash object which will be used to checksum each chunk.
	h hash.Hash

	// chunkSize is the data chunk size. chunkSize is immutable.
	chunkSize int

	// done is the current chunk position.
	done int

	// prevHash is the previous hash value.
	prevHash [sha256.Size]byte

	// buf is used to buffer the output.
	buf []byte

	// closed indicates whether the file has been closed.
	closed bool
}

var _ io.Writer = (*SimpleWriter)(nil)
var _ io.Closer = (*SimpleWriter)(nil)

// NewSimpleWriter returns a new non-compressing writer. If key is non-nil,
// hash values are generated and written out for compressed bytes. See package
// comments for details. chunkSize is the buffer size used for buffering. Large
// writes are not buffered and written out directly as a single chunk.
func NewSimpleWriter(out io.Writer, key []byte, chunkSize uint32) *SimpleWriter {
	if len(key) == 0 {
		// Since there is no key, this image doesn't use the data integrity stream
		// format mentioned in package comments. We can just use a bufio writer.
		return &SimpleWriter{
			base:   out,
			bufOut: bufio.NewWriterSize(out, defaultBufSize),
		}
	}

	return &SimpleWriter{
		base:      out,
		h:         hmac.New(sha256.New, key),
		chunkSize: int(chunkSize),
		// Allocate space for the data size header and the hash.
		buf: make([]byte, 4+chunkSize+sha256.Size),
	}
}

// Write implements io.Writer.Write.
func (w *SimpleWriter) Write(p []byte) (int, error) {
	// Did we close already?
	if w.closed {
		return 0, io.ErrUnexpectedEOF
	}

	if w.bufOut != nil {
		return w.bufOut.Write(p)
	}

	total := 0
	for len(p) > 0 {
		if len(p) > w.chunkSize && w.done == 0 {
			// If the payload is larger than the chunk size and we are not in the
			// middle of writing another chunk, we can just write it out as one chunk.
			n, err := w.directWrite(p)
			return total + n, err
		}

		// Copy to buffer.
		n := copy(w.buf[4+w.done:4+w.chunkSize], p)

		// Update state.
		w.done += n
		p = p[n:]
		total += n

		// Flush if necessary.
		if w.done >= w.chunkSize {
			if err := w.flush(); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

// Precondition: w.done == 0.
func (w *SimpleWriter) directWrite(p []byte) (int, error) {
	// Write the data size.
	binary.BigEndian.PutUint32(w.buf[:4], uint32(len(p)))
	if _, err := w.base.Write(w.buf[:4]); err != nil {
		return 0, err
	}

	// Write the data.
	n, err := w.base.Write(p)
	if err != nil {
		return n, err
	}

	// Write the hash. Compute it as per package comments.
	w.h.Reset()
	_, _ = w.h.Write(p)
	_, _ = w.h.Write(w.buf[:4])
	_, _ = w.h.Write(w.prevHash[:])
	// Compute the hash into prevHash, now that we don't need the old value.
	// Pass a 32-byte capacity slice (with 0 length) to avoid allocation.
	w.h.Sum(w.prevHash[0:0:sha256.Size])
	_, err = w.base.Write(w.prevHash[:sha256.Size])
	return n, err
}

func (w *SimpleWriter) flush() error {
	if w.done <= 0 {
		return nil
	}

	// Add the data size header at the beginning of the buffer.
	binary.BigEndian.PutUint32(w.buf[:4], uint32(w.done))

	// Compute the hash by writing the data followed by data size.
	w.h.Reset()
	_, _ = w.h.Write(w.buf[4 : 4+w.done])
	_, _ = w.h.Write(w.buf[:4])
	_, _ = w.h.Write(w.prevHash[:])

	// Compute the hash into prevHash, now that we don't need the old value.
	// Pass a 32-byte capacity slice (with 0 length) to avoid allocation.
	w.h.Sum(w.prevHash[0:0:sha256.Size])
	// Write it after the data section in the buffer.
	copy(w.buf[4+w.done:4+w.done+sha256.Size], w.prevHash[:sha256.Size])

	// Write out to the stream.
	_, err := w.base.Write(w.buf[:4+w.done+sha256.Size])

	// Reset state.
	w.done = 0
	return err
}

// Close implements io.Closer.Close.
func (w *SimpleWriter) Close() error {
	// Did we already close? After the call to Close, we always mark as
	// closed, regardless of whether the flush is successful.
	if w.closed {
		return io.ErrUnexpectedEOF
	}
	w.closed = true

	// Flush buffers.
	if w.bufOut != nil {
		if err := w.bufOut.Flush(); err != nil {
			return err
		}
	} else {
		if err := w.flush(); err != nil {
			return err
		}
	}

	// Close the underlying writer (if necessary).
	if closer, ok := w.base.(io.Closer); ok {
		return closer.Close()
	}

	w.bufOut = nil
	w.base = nil
	w.buf = nil

	return nil
}
