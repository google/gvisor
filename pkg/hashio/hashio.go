// Copyright 2018 Google Inc.
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

/*
Package hashio provides hash-verified I/O streams.

The I/O stream format is defined as follows.

/-----------------------------------------\
|                 payload                 |
+-----------------------------------------+
|                  hash                   |
+-----------------------------------------+
|                 payload                 |
+-----------------------------------------+
|                  hash                   |
+-----------------------------------------+
|                 ......                  |
\-----------------------------------------/

Payload bytes written to / read from the stream are automatically split
into segments, each followed by a hash. All data read out must have already
passed hash verification. Hence the client code can safely do any kind of
(stream) processing of these data.
*/
package hashio

import (
	"crypto/hmac"
	"errors"
	"hash"
	"io"
	"sync"
)

// SegmentSize is the unit we split payload data and insert hash at.
const SegmentSize = 8 * 1024

// ErrHashMismatch is returned if the ErrHashMismatch does not match.
var ErrHashMismatch = errors.New("hash mismatch")

// writer computes hashs during writes.
type writer struct {
	mu      sync.Mutex
	w       io.Writer
	h       hash.Hash
	written int
	closed  bool
	hashv   []byte
}

// NewWriter creates a hash-verified IO stream writer.
func NewWriter(w io.Writer, h hash.Hash) io.WriteCloser {
	return &writer{
		w:     w,
		h:     h,
		hashv: make([]byte, h.Size()),
	}
}

// Write writes the given data.
func (w *writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Did we already close?
	if w.closed {
		return 0, io.ErrUnexpectedEOF
	}

	for done := 0; done < len(p); {
		// Slice the data at segment boundary.
		left := SegmentSize - w.written
		if left > len(p[done:]) {
			left = len(p[done:])
		}

		// Write the rest of the segment and write to hash writer the
		// same number of bytes. Hash.Write may never return an error.
		n, err := w.w.Write(p[done : done+left])
		w.h.Write(p[done : done+left])
		w.written += n
		done += n

		// And only check the actual write errors here.
		if n == 0 && err != nil {
			return done, err
		}

		// Write hash if starting a new segment.
		if w.written == SegmentSize {
			if err := w.closeSegment(); err != nil {
				return done, err
			}
		}
	}

	return len(p), nil
}

// closeSegment closes the current segment and writes out its hash.
func (w *writer) closeSegment() error {
	// Serialize and write the current segment's hash.
	hashv := w.h.Sum(w.hashv[:0])
	for done := 0; done < len(hashv); {
		n, err := w.w.Write(hashv[done:])
		done += n
		if n == 0 && err != nil {
			return err
		}
	}
	w.written = 0 // reset counter.
	return nil
}

// Close writes the final hash to the stream and closes the underlying Writer.
func (w *writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Did we already close?
	if w.closed {
		return io.ErrUnexpectedEOF
	}

	// Always mark as closed, regardless of errors.
	w.closed = true

	// Write the final segment.
	if err := w.closeSegment(); err != nil {
		return err
	}

	// Call the underlying closer.
	if c, ok := w.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// reader computes and verifies hashs during reads.
type reader struct {
	mu sync.Mutex
	r  io.Reader
	h  hash.Hash

	// data is remaining verified but unused payload data. This is
	// populated on short reads and may be consumed without any
	// verification.
	data [SegmentSize]byte

	// index is the index into data above.
	index int

	// available is the amount of valid data above.
	available int

	// hashv is the read hash for the current segment.
	hashv []byte

	// computev is the computed hash for the current segment.
	computev []byte
}

// NewReader creates a hash-verified IO stream reader.
func NewReader(r io.Reader, h hash.Hash) io.Reader {
	return &reader{
		r:        r,
		h:        h,
		hashv:    make([]byte, h.Size()),
		computev: make([]byte, h.Size()),
	}
}

// readSegment reads a segment and hash vector.
//
// Precondition: datav must have length SegmentSize.
func (r *reader) readSegment(datav []byte) (data []byte, err error) {
	// Make two reads: the first is the segment, the second is the hash
	// which needs verification. We may need to adjust the resulting slices
	// in the case of short reads.
	for done := 0; done < SegmentSize; {
		n, err := r.r.Read(datav[done:])
		done += n
		if n == 0 && err == io.EOF {
			if done == 0 {
				// No data at all.
				return nil, io.EOF
			} else if done < len(r.hashv) {
				// Not enough for a hash.
				return nil, ErrHashMismatch
			}
			// Truncate the data and copy to the hash.
			copy(r.hashv, datav[done-len(r.hashv):])
			datav = datav[:done-len(r.hashv)]
			return datav, nil
		} else if n == 0 && err != nil {
			return nil, err
		}
	}
	for done := 0; done < len(r.hashv); {
		n, err := r.r.Read(r.hashv[done:])
		done += n
		if n == 0 && err == io.EOF {
			// Copy over from the data.
			missing := len(r.hashv) - done
			copy(r.hashv[missing:], r.hashv[:done])
			copy(r.hashv[:missing], datav[len(datav)-missing:])
			datav = datav[:len(datav)-missing]
			return datav, nil
		} else if n == 0 && err != nil {
			return nil, err
		}
	}
	return datav, nil
}

// verifyHash verifies the given hash.
//
// The passed hash will be returned to the pool.
func (r *reader) verifyHash(datav []byte) error {
	for done := 0; done < len(datav); {
		n, _ := r.h.Write(datav[done:])
		done += n
	}
	computev := r.h.Sum(r.computev[:0])
	if !hmac.Equal(r.hashv, computev) {
		return ErrHashMismatch
	}
	return nil
}

// Read reads the data.
func (r *reader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for done := 0; done < len(p); {
		// Check for pending data.
		if r.index < r.available {
			n := copy(p[done:], r.data[r.index:r.available])
			done += n
			r.index += n
			continue
		}

		// Prepare the next read.
		var (
			datav  []byte
			inline bool
		)

		// We need to read a new segment. Can we read directly?
		if len(p[done:]) >= SegmentSize {
			datav = p[done : done+SegmentSize]
			inline = true
		} else {
			datav = r.data[:]
			inline = false
		}

		// Read the next segments.
		datav, err := r.readSegment(datav)
		if err != nil && err != io.EOF {
			return 0, err
		} else if err == io.EOF {
			return done, io.EOF
		}
		if err := r.verifyHash(datav); err != nil {
			return done, err
		}

		if inline {
			// Move the cursor.
			done += len(datav)
		} else {
			// Reset index & available.
			r.index = 0
			r.available = len(datav)
		}
	}

	return len(p), nil
}
