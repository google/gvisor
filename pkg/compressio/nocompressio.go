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
	"bytes"
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

	// scratch is a 4-byte scratch buffer used for 32-bit integers.
	scratch [4]byte
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
		if _, err := io.ReadFull(r.in, r.scratch[:]); err != nil {
			return 0, err
		}

		r.chunkSize = binary.BigEndian.Uint32(r.scratch[:])
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

	_, _ = r.h.Write(p[:n])
	r.done += uint32(n)
	if r.done >= r.chunkSize {
		binary.BigEndian.PutUint32(r.scratch[:], r.chunkSize)
		r.h.Write(r.scratch[:])

		sum := r.h.Sum(nil)
		readerSum := make([]byte, len(sum))
		if _, err := io.ReadFull(r.in, readerSum); err != nil {
			if err == io.EOF {
				return n, io.ErrUnexpectedEOF
			}
			return n, err
		}

		if !hmac.Equal(readerSum, sum) {
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

	// out is a buffered writer.
	out *bufio.Writer

	// h is the hash object.
	h hash.Hash

	// closed indicates whether the file has been closed.
	closed bool

	// scratch is a 4-byte scratch buffer used for 32-bit integers.
	scratch [4]byte
}

var _ io.Writer = (*SimpleWriter)(nil)
var _ io.Closer = (*SimpleWriter)(nil)

// NewSimpleWriter returns a new non-compressing writer. If key is non-nil,
// hash values are generated and written out for compressed bytes. See package
// comments for details.
func NewSimpleWriter(out io.Writer, key []byte) *SimpleWriter {
	w := &SimpleWriter{
		base: out,
		out:  bufio.NewWriterSize(out, defaultBufSize),
	}
	if key != nil {
		w.h = hmac.New(sha256.New, key)
	}
	return w
}

// Write implements io.Writer.Write.
func (w *SimpleWriter) Write(p []byte) (int, error) {
	// Did we close already?
	if w.closed {
		return 0, io.ErrUnexpectedEOF
	}

	if w.h == nil {
		return w.out.Write(p)
	}

	l := uint32(len(p))

	// chunk length
	binary.BigEndian.PutUint32(w.scratch[:], l)
	if _, err := w.out.Write(w.scratch[:]); err != nil {
		return 0, err
	}

	// Write out to the stream.
	n, err := w.out.Write(p)
	if err != nil {
		return n, err
	}

	// Write out the hash.

	// chunk data
	_, _ = w.h.Write(p)

	// chunk length
	binary.BigEndian.PutUint32(w.scratch[:], l)
	w.h.Write(w.scratch[:])

	sum := w.h.Sum(nil)
	w.h.Reset()
	if _, err := io.CopyN(w.out, bytes.NewReader(sum), int64(len(sum))); err != nil {
		return n, err
	}

	return n, nil
}

// Close implements io.Closer.Close.
func (w *SimpleWriter) Close() error {
	// Did we already close? After the call to Close, we always mark as
	// closed, regardless of whether the flush is successful.
	if w.closed {
		return io.ErrUnexpectedEOF
	}
	w.closed = true

	// Flush buffered writer
	if err := w.out.Flush(); err != nil {
		return err
	}

	// Close the underlying writer (if necessary).
	if closer, ok := w.base.(io.Closer); ok {
		return closer.Close()
	}

	w.out = nil
	w.base = nil

	return nil
}
