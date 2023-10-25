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
// The stream format is defined as follows.
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

// SimpleReader is a reader from uncompressed image.
type SimpleReader struct {
	// in is the source.
	in io.Reader

	// key is the key used to create hash objects.
	key []byte

	// h is the hash object.
	h hash.Hash

	// current data chunk size
	chunkSize uint32

	// current chunk position
	done uint32
}

var _ io.Reader = (*SimpleReader)(nil)

const (
	defaultBufSize = 256 * 1024
)

// NewSimpleReader returns a new (uncompressed) reader. If key is non-nil, the data stream
// is assumed to contain expected hash values. See package comments for
// details.
func NewSimpleReader(in io.Reader, key []byte) (*SimpleReader, error) {
	r := &SimpleReader{
		in:  bufio.NewReaderSize(in, defaultBufSize),
		key: key,
	}

	if key != nil {
		r.h = hmac.New(sha256.New, key)
	}

	return r, nil
}

// ReadByte implements wire.Reader.ReadByte.
func (r *SimpleReader) ReadByte() (byte, error) {
	var p [1]byte
	n, err := r.Read(p[:])
	if n != 1 {
		return p[0], err
	}
	// Suppress EOF.
	return p[0], nil
}

// Read implements io.Reader.Read.
func (r *SimpleReader) Read(p []byte) (int, error) {
	var scratch [4]byte

	if len(p) == 0 {
		return r.in.Read(p)
	}

	// need next chunk?
	if r.done >= r.chunkSize {
		if _, err := io.ReadFull(r.in, scratch[:]); err != nil {
			return 0, err
		}

		r.chunkSize = binary.BigEndian.Uint32(scratch[:])
		r.done = 0
		if r.key != nil {
			r.h.Reset()
		}

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

	if r.key != nil {
		_, _ = r.h.Write(p[:n])
	}

	r.done += uint32(n)
	if r.done >= r.chunkSize {
		if r.key != nil {
			binary.BigEndian.PutUint32(scratch[:], r.chunkSize)
			r.h.Write(scratch[:4])

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

	// key is the key used to create hash objects.
	key []byte

	// closed indicates whether the file has been closed.
	closed bool
}

var _ io.Writer = (*SimpleWriter)(nil)
var _ io.Closer = (*SimpleWriter)(nil)

// NewSimpleWriter returns a new non-compressing writer. If key is non-nil, hash values are
// generated and written out for compressed bytes. See package comments for
// details.
func NewSimpleWriter(out io.Writer, key []byte) (*SimpleWriter, error) {
	return &SimpleWriter{
		base: out,
		out:  bufio.NewWriterSize(out, defaultBufSize),
		key:  key,
	}, nil
}

// WriteByte implements wire.Writer.WriteByte.
//
// Note that this implementation is necessary on the object itself, as an
// interface-based dispatch cannot tell whether the array backing the slice
// escapes, therefore the all bytes written will generate an escape.
func (w *SimpleWriter) WriteByte(b byte) error {
	var p [1]byte
	p[0] = b
	n, err := w.Write(p[:])
	if n != 1 {
		return err
	}
	return nil
}

// Write implements io.Writer.Write.
func (w *SimpleWriter) Write(p []byte) (int, error) {
	var scratch [4]byte

	// Did we close already?
	if w.closed {
		return 0, io.ErrUnexpectedEOF
	}

	l := uint32(len(p))

	// chunk length
	binary.BigEndian.PutUint32(scratch[:], l)
	if _, err := w.out.Write(scratch[:4]); err != nil {
		return 0, err
	}

	// Write out to the stream.
	n, err := w.out.Write(p)
	if err != nil {
		return n, err
	}

	if w.key != nil {
		h := hmac.New(sha256.New, w.key)

		// chunk data
		_, _ = h.Write(p)

		// chunk length
		binary.BigEndian.PutUint32(scratch[:], l)
		h.Write(scratch[:4])

		sum := h.Sum(nil)
		if _, err := io.CopyN(w.out, bytes.NewReader(sum), int64(len(sum))); err != nil {
			return n, err
		}
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
