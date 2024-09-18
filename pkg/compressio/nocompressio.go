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

// SimpleReader is a reader for uncompressed image containing hashes.
type SimpleReader struct {
	// in is the source.
	in io.Reader

	// h is the hash object.
	h hash.Hash

	// current data chunk size
	chunkSize uint32

	// current chunk position
	done uint32

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
func NewSimpleReader(in io.Reader, key []byte) io.Reader {
	bin := bufio.NewReaderSize(in, defaultBufSize)
	if key == nil {
		// Since there is no key, this image doesn't use the data integrity stream
		// format mentioned in package comments. We can just use the bufio reader.
		return bin
	}
	return &SimpleReader{
		in: bin,
		h:  hmac.New(sha256.New, key),
	}
}

// Read implements io.Reader.Read.
func (r *SimpleReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return r.in.Read(p)
	}

	// need next chunk?
	if r.done >= r.chunkSize {
		if _, err := io.ReadFull(r.in, r.scratch[:4]); err != nil {
			return 0, err
		}

		r.chunkSize = binary.BigEndian.Uint32(r.scratch[:4])
		r.done = 0
		r.h.Reset()

		if r.chunkSize == 0 {
			// this must not happen
			return 0, io.ErrNoProgress
		}
	}

	toRead := uint32(len(p))
	// can't read more than what's left
	if toRead > r.chunkSize-r.done {
		toRead = r.chunkSize - r.done
	}

	n, err := r.in.Read(p[:toRead])
	if err != nil {
		if err == io.EOF {
			// this only can happen if storage or data size is corrupted,
			// but we have no other means to detect it earlier as we store
			// hash after the data block.
			return n, ErrHashMismatch
		}
		return n, err
	}

	// Add data to hash.
	_, _ = r.h.Write(p[:n])
	r.done += uint32(n)
	// Is current chunk done?
	if r.done >= r.chunkSize {
		// Add data size to hash.
		binary.BigEndian.PutUint32(r.scratch[:4], r.chunkSize)
		r.h.Write(r.scratch[:4])

		// Add previous hash to hash.
		r.h.Write(r.prevHash[:])

		// Compute the hash into prevHash, now that we don't need the old value.
		// Pass a 32-byte capacity slice (with 0 length) to avoid allocation.
		r.h.Sum(r.prevHash[0:0:sha256.Size])

		// Read the hash value from the stream.
		if _, err := io.ReadFull(r.in, r.scratch[:]); err != nil {
			if err == io.EOF {
				return n, io.ErrUnexpectedEOF
			}
			return n, err
		}

		if !hmac.Equal(r.scratch[:sha256.Size], r.prevHash[:sha256.Size]) {
			return n, ErrHashMismatch
		}

		r.done = 0
		r.chunkSize = 0
	}

	return n, nil
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
	if key == nil {
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
