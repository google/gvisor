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

// Package compressio provides parallel compression and decompression, as well
// as optional SHA-256 hashing. It also provides another storage variant
// (nocompressio) that does not compress data but tracks its integrity.
//
// The stream format is defined as follows.
//
// /------------------------------------------------------\
// |                 chunk size (4-bytes)                 |
// +------------------------------------------------------+
// |              (optional) hash (32-bytes)              |
// +------------------------------------------------------+
// |           compressed data size (4-bytes)             |
// +------------------------------------------------------+
// |                   compressed data                    |
// +------------------------------------------------------+
// |              (optional) hash (32-bytes)              |
// +------------------------------------------------------+
// |           compressed data size (4-bytes)             |
// +------------------------------------------------------+
// |                       ......                         |
// \------------------------------------------------------/
//
// where each subsequent hash is calculated from the following items in order
//
//	compressed data
//	compressed data size
//	previous hash
//
// so the stream integrity cannot be compromised by switching and mixing
// compressed chunks.
package compressio

import (
	"bytes"
	"compress/flate"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"runtime"

	"gvisor.dev/gvisor/pkg/sync"
)

var bufPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(nil)
	},
}

var chunkPool = sync.Pool{
	New: func() any {
		return new(chunk)
	},
}

// chunk is a unit of work.
//
// Sending a chunk on a worker's input transfers its mutable state and buffers
// to that worker until the result is received. Inline buffers alias caller
// storage, so Read and Write must receive their results before returning,
// including on error. checklocks cannot express this channel-based ownership.
type chunk struct {
	// compressed is compressed data.
	//
	// This will always be returned to the bufPool directly when work has
	// finished (in schedule) and therefore must be allocated.
	compressed *bytes.Buffer

	// uncompressed is the uncompressed data.
	//
	// This is not returned to the bufPool automatically, since it may
	// correspond to a inline slice (provided directly to Read or Write).
	uncompressed *bytes.Buffer

	// The current hash object. Only used in compress mode.
	h hash.Hash

	// The hash from previous chunks. Only used in uncompress mode.
	lastSum []byte

	// The expected hash after current chunk. Only used in uncompress mode.
	sum []byte
}

// newChunk allocates a new chunk object (or pulls one from the pool). Buffers
// will be allocated if nil is provided for compressed or uncompressed.
func newChunk(lastSum []byte, sum []byte, compressed *bytes.Buffer, uncompressed *bytes.Buffer) *chunk {
	c := chunkPool.Get().(*chunk)
	c.lastSum = lastSum
	c.sum = sum
	if compressed != nil {
		c.compressed = compressed
	} else {
		c.compressed = bufPool.Get().(*bytes.Buffer)
	}
	if uncompressed != nil {
		c.uncompressed = uncompressed
	} else {
		c.uncompressed = bufPool.Get().(*bytes.Buffer)
	}
	return c
}

// result is the result of some work; it includes the original chunk.
type result struct {
	*chunk
	err error
}

// worker is a compression/decompression worker.
//
// The associated worker goroutine reads in uncompressed buffers from input and
// writes compressed buffers to its output. Alternatively, the worker reads
// compressed buffers from input and writes uncompressed buffers to its output.
//
// The goroutine will exit when input is closed, and the goroutine will close
// output.
type worker struct {
	// These handles are initialized before work starts, then immutable.
	hashPool *hashPool
	input    chan *chunk
	output   chan result

	// scratch is a temporary buffer used for marshalling. This is declared
	// up front here to avoid reallocation. Only this worker's goroutine uses it.
	scratch [4]byte
}

// work is the main work routine; see worker.
func (w *worker) work(compress bool, level int) {
	defer close(w.output)

	var h hash.Hash

	for c := range w.input {
		if h == nil && w.hashPool != nil {
			h = w.hashPool.getHash()
		}
		if compress {
			mw := io.Writer(c.compressed)
			if h != nil {
				mw = io.MultiWriter(mw, h)
			}

			// Encode this slice.
			fw, err := flate.NewWriter(mw, level)
			if err != nil {
				w.output <- result{c, err}
				continue
			}

			// Encode the input.
			if _, err := io.CopyN(fw, c.uncompressed, int64(c.uncompressed.Len())); err != nil {
				w.output <- result{c, err}
				continue
			}
			if err := fw.Close(); err != nil {
				w.output <- result{c, err}
				continue
			}

			// Write the hash, if enabled.
			if h != nil {
				binary.BigEndian.PutUint32(w.scratch[:], uint32(c.compressed.Len()))
				h.Write(w.scratch[:4])
				c.h = h
				h = nil
			}
		} else {
			// Check the hash of the compressed contents.
			if h != nil {
				h.Write(c.compressed.Bytes())
				binary.BigEndian.PutUint32(w.scratch[:], uint32(c.compressed.Len()))
				h.Write(w.scratch[:4])
				io.CopyN(h, bytes.NewReader(c.lastSum), int64(len(c.lastSum)))

				sum := h.Sum(nil)
				h.Reset()
				if !hmac.Equal(c.sum, sum) {
					w.output <- result{c, ErrHashMismatch}
					continue
				}
			}

			// Decode this slice.
			fr := flate.NewReader(c.compressed)

			// Decode the input.
			if _, err := io.Copy(c.uncompressed, fr); err != nil {
				w.output <- result{c, err}
				continue
			}
		}

		// Send the output.
		w.output <- result{c, nil}
	}
}

type hashPool struct {
	mu sync.Mutex

	// key is a private copy of the key used to create hash objects. It is
	// immutable after construction, including during lazy worker setup.
	key []byte

	// hashes is the hash object free list. Note that this cannot be
	// globally shared across readers or writers, as it is key-specific.
	//
	// +checklocks:mu
	hashes []hash.Hash
}

// getHash gets a hash object for the pool. It should only be called when the
// pool key is non-empty.
//
// +checklocksexclude:p.mu
func (p *hashPool) getHash() hash.Hash {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.hashes) == 0 {
		return hmac.New(sha256.New, p.key)
	}

	h := p.hashes[len(p.hashes)-1]
	p.hashes = p.hashes[:len(p.hashes)-1]
	return h
}

// putHash resets h and returns it to the free list.
//
// +checklocksexclude:p.mu
func (p *hashPool) putHash(h hash.Hash) {
	h.Reset()

	p.mu.Lock()
	defer p.mu.Unlock()

	p.hashes = append(p.hashes, h)
}

// pool is common functionality for reader/writers.
type pool struct {
	// mu serializes construction, Reader.Read, Writer.Write, Writer.Close,
	// and finalizer cleanup, including synchronous completion callbacks.
	mu sync.Mutex

	// workers are the compression/decompression workers.
	//
	// +checklocks:mu
	workers []worker

	// chunkSize is the chunk size. This is the first four bytes in the
	// stream and is shared across both the reader and writer. It is immutable
	// after construction.
	chunkSize uint32

	// nextInput is the next worker for input (scheduling).
	//
	// +checklocks:mu
	nextInput int

	// nextOutput is the next worker for output (result).
	//
	// +checklocks:mu
	nextOutput int

	// buf is the current active buffer; the exact semantics of this buffer
	// depend on whether this is a reader or a writer.
	//
	// +checklocks:mu
	buf *bytes.Buffer

	// err is the first returned terminal Read or Write error. Submitted work is
	// drained before returning it, so later calls must not schedule more work.
	//
	// +checklocks:mu
	err error

	// lastSum records the hash of the last chunk processed.
	//
	// +checklocks:mu
	lastSum []byte

	// hashPool is the hash object pool. It cannot be embedded into pool
	// itself as worker refers to it and that would stop pool from being
	// GCed.
	//
	// +checklocks:mu
	hashPool *hashPool
}

// init initializes the worker pool.
//
// This should only be called once.
//
// +checklocks:p.mu
func (p *pool) init(key []byte, workers int, compress bool, level int) {
	if len(key) > 0 {
		p.hashPool = &hashPool{key: bytes.Clone(key)}
	}
	p.workers = make([]worker, workers)
	for i := 0; i < len(p.workers); i++ {
		p.workers[i] = worker{
			hashPool: p.hashPool,
			input:    make(chan *chunk, 1),
			output:   make(chan result, 1),
		}
		go p.workers[i].work(compress, level) // S/R-SAFE: In save path only.
	}
	runtime.SetFinalizer(p, func(p *pool) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.stop()
	})
}

// stop closes worker inputs and drains all submitted work. Worker goroutines
// may still be exiting when it returns, but no longer access submitted buffers.
//
// +checklocks:p.mu
func (p *pool) stop() {
	for i := 0; i < len(p.workers); i++ {
		close(p.workers[i].input)
	}
	// Drain outstanding results since p.schedule(c=nil) may have returned
	// early if any worker emitted an error.
	if len(p.workers) != 0 {
		for p.nextOutput < p.nextInput {
			// Reclaim completed chunks even if their work failed. No results
			// are delivered to the caller during cleanup.
			_ = handleResult(<-p.workers[(p.nextOutput+1)%len(p.workers)].output, func(*chunk) error {
				return nil
			})
			p.nextOutput++
		}
	}
	p.workers = nil
	p.hashPool = nil
}

// handleResult calls callback synchronously if r.err is nil, then recycles the
// chunk. callback may retain the uncompressed buffer, but not the chunk itself.
func handleResult(r result, callback func(*chunk) error) error {
	defer func() {
		r.chunk.compressed.Reset()
		bufPool.Put(r.chunk.compressed)
		// Inline chunks can reference caller-owned storage. Drop those
		// references without returning the caller's buffer to bufPool.
		*r.chunk = chunk{}
		chunkPool.Put(r.chunk)
	}()
	if r.err != nil {
		return r.err
	}
	return callback(r.chunk)
}

// schedule schedules the given buffers.
//
// If c is non-nil, then it will return as soon as the chunk is scheduled. If c
// is nil, then it will return only when no more work is left to do.
//
// If no callback function is provided, then the output channel will be
// ignored.  You must be sure that the input is schedulable in this case.
//
// callback is invoked synchronously with p.mu held. It must preserve that lock
// and not reenter methods that acquire it. checklocks does not propagate the
// held lock through this callback parameter.
//
// +checklocks:p.mu
func (p *pool) schedule(c *chunk, callback func(*chunk) error) error {
	for {
		var (
			inputChan  chan *chunk
			outputChan chan result
		)
		if c != nil && len(p.workers) != 0 {
			inputChan = p.workers[(p.nextInput+1)%len(p.workers)].input
		}
		if callback != nil && p.nextOutput != p.nextInput && len(p.workers) != 0 {
			outputChan = p.workers[(p.nextOutput+1)%len(p.workers)].output
		}
		if inputChan == nil && outputChan == nil {
			return nil
		}

		select {
		case inputChan <- c:
			p.nextInput++
			return nil
		case r := <-outputChan:
			p.nextOutput++
			if err := handleResult(r, callback); err != nil {
				return err
			}
		}
	}
}

// Reader is a compressed reader.
type Reader struct {
	pool

	// in is the source; the interface value is immutable. Read calls it with
	// mu held, so it must not reenter Reader.Read.
	in io.ReadCloser

	// scratch is a temporary buffer used for marshalling. This is declared
	// unfront here to avoid reallocation.
	//
	// +checklocks:mu
	scratch [4]byte
}

var _ io.Reader = (*Reader)(nil)

// NewReader returns a new compressed reader. If key is non-empty, the data stream
// is assumed to contain expected hash values, which will be compared against
// hash values computed from the compressed bytes. See package comments for
// details.
func NewReader(in io.ReadCloser, key []byte) (*Reader, error) {
	r := &Reader{
		in: in,
	}
	// init registers a finalizer. Order subsequent initialization before
	// finalizer cleanup, including when a header read fails.
	r.mu.Lock()
	defer r.mu.Unlock()

	// Use double buffering for read.
	r.init(key, 2*runtime.GOMAXPROCS(0), false, 0)

	if _, err := io.ReadFull(in, r.scratch[:4]); err != nil {
		return nil, err
	}
	r.chunkSize = binary.BigEndian.Uint32(r.scratch[:4])

	if r.hashPool != nil {
		h := r.hashPool.getHash()
		binary.BigEndian.PutUint32(r.scratch[:], r.chunkSize)
		h.Write(r.scratch[:4])
		r.lastSum = h.Sum(nil)
		r.hashPool.putHash(h)
		sum := make([]byte, len(r.lastSum))
		if _, err := io.ReadFull(r.in, sum); err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if !hmac.Equal(r.lastSum, sum) {
			return nil, ErrHashMismatch
		}
	}

	return r, nil
}

// errNewBuffer is returned when a new buffer is completed.
var errNewBuffer = errors.New("buffer ready")

// ErrHashMismatch is returned if the hash does not match.
var ErrHashMismatch = errors.New("hash mismatch")

// Read implements io.Reader.Read.
//
// +checklocksexclude:r.mu
func (r *Reader) Read(p []byte) (done int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.err != nil {
		return 0, r.err
	}
	defer func() {
		if err != nil {
			r.err = err
			// Workers may still be writing directly into p, even when an
			// input read or an earlier worker failed.
			r.stop()
			r.buf = nil
		}
	}()

	// Total bytes pending in the asynchronous workers for buffers. This is
	// used to process the proper regions of the input as inline buffers.
	var (
		pendingPre    = r.nextInput - r.nextOutput
		pendingInline = 0
	)

	// Define our callback for completed work.
	callback := func(c *chunk) error {
		// Check for an inline buffer.
		if pendingPre == 0 && pendingInline > 0 {
			pendingInline--
			done += c.uncompressed.Len()
			return nil
		}

		// Copy the resulting buffer to our intermediate one, and
		// return errNewBuffer to ensure that we aren't called a second
		// time. This error code is handled specially below.
		//
		// Read returns c.uncompressed to bufPool after consuming it.
		if pendingPre > 0 {
			pendingPre--
		}
		// schedule invokes this callback with r.mu held, but checklocks does
		// not propagate the lock state through the callback parameter.
		r.buf = c.uncompressed // +checklocksignore
		return errNewBuffer
	}

	for done < len(p) {
		// Do we have buffered data available?
		if r.buf != nil {
			n, err := r.buf.Read(p[done:])
			done += n
			if err == io.EOF {
				// This is the uncompressed buffer, it can be
				// returned to the pool at this point.
				r.buf.Reset()
				bufPool.Put(r.buf)
				r.buf = nil
			} else if err != nil {
				// Should never happen.
				return done, err
			}
			continue
		}

		// Read the length of the next chunk and reset the
		// reader. The length is used to limit the reader.
		//
		// See writer.flush.
		if _, err := io.ReadFull(r.in, r.scratch[:4]); err != nil {
			// This is generally okay as long as there
			// are still buffers outstanding. We actually
			// just wait for completion of those buffers here
			// and continue our loop.
			if err := r.schedule(nil, callback); err == nil {
				// We've actually finished all buffers; this is
				// the normal EOF exit path.
				return done, io.EOF
			} else if err == errNewBuffer {
				// A new buffer is now available.
				continue
			} else {
				// Some other error occurred; we cannot
				// process any further.
				return done, err
			}
		}
		l := binary.BigEndian.Uint32(r.scratch[:4])

		// Read this chunk and schedule decompression.
		compressed := bufPool.Get().(*bytes.Buffer)
		if _, err := io.CopyN(compressed, r.in, int64(l)); err != nil {
			// Some other error occurred; see above.
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return done, err
		}

		var sum []byte
		if r.hashPool != nil {
			sum = make([]byte, len(r.lastSum))
			if _, err := io.ReadFull(r.in, sum); err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return done, err
			}
		}

		// Are we doing inline decoding?
		//
		// Note that we need to check the length here against
		// bytes.MinRead, since the bytes library will choose to grow
		// the slice if the available capacity is not at least
		// bytes.MinRead. This limits inline decoding to chunkSizes
		// that are at least bytes.MinRead (which is not unreasonable).
		var c *chunk
		start := done + ((pendingPre + pendingInline) * int(r.chunkSize))
		if len(p) >= start+int(r.chunkSize) && len(p) >= start+bytes.MinRead {
			c = newChunk(r.lastSum, sum, compressed, bytes.NewBuffer(p[start:start]))
			pendingInline++
		} else {
			c = newChunk(r.lastSum, sum, compressed, nil)
		}
		r.lastSum = sum
		if err := r.schedule(c, callback); err == errNewBuffer {
			// A new buffer was completed while we were reading.
			// That's great, but we need to force schedule the
			// current buffer so that it does not get lost.
			//
			// It is safe to pass nil as an output function here,
			// because we know that we just freed up a slot above.
			_ = r.schedule(c, nil)
		} else if err != nil {
			// Some other error occurred; see above.
			return done, err
		}
	}

	// Make sure that everything has been decoded successfully, otherwise
	// parts of p may not actually have completed.
	for pendingInline > 0 {
		if err := r.schedule(nil, func(c *chunk) error {
			if err := callback(c); err != nil {
				return err
			}
			// The nil case means that an inline buffer has
			// completed. The callback has already decremented
			// pendingInline, so we just return an
			// error to check the top of the loop again.
			return errNewBuffer
		}); err != errNewBuffer {
			// Some other error occurred; see above.
			return done, err
		}
	}

	// Need to return done here, since it may have been adjusted by the
	// callback to compensation for partial reads on some inline buffer.
	return done, nil
}

// Close implements io.Closer.Close.
// It forwards to the source without taking mu, allowing the source to interrupt
// a blocked Read.
// Concurrent Read and Close require support from the underlying source.
func (r *Reader) Close() error {
	return r.in.Close()
}

// Writer is a compressed writer.
type Writer struct {
	pool

	// out is the underlying writer; the interface value is immutable.
	// Its Write and Close methods are called with mu held and must not reenter
	// Writer.Write or Writer.Close.
	out io.Writer

	// closed indicates whether the file has been closed.
	//
	// +checklocks:mu
	closed bool

	// scratch is a temporary buffer used for marshalling. This is declared
	// unfront here to avoid reallocation.
	//
	// +checklocks:mu
	scratch [4]byte
}

var _ io.Writer = (*Writer)(nil)

// NewWriter returns a new compressed writer. If key is non-empty, hash values are
// generated and written out for compressed bytes. See package comments for
// details.
//
// The recommended chunkSize is on the order of 1M. Extra memory may be
// buffered (in the form of read-ahead, or buffered writes), and is limited to
// O(chunkSize * [1+GOMAXPROCS]).
func NewWriter(out io.Writer, key []byte, chunkSize uint32, level int) (*Writer, error) {
	w := &Writer{
		pool: pool{
			chunkSize: chunkSize,
			buf:       bufPool.Get().(*bytes.Buffer),
		},
		out: out,
	}
	// init registers a finalizer. Order subsequent initialization before
	// finalizer cleanup, including when a header write fails.
	w.mu.Lock()
	defer w.mu.Unlock()
	w.init(key, 1+runtime.GOMAXPROCS(0), true, level)

	binary.BigEndian.PutUint32(w.scratch[:], chunkSize)
	if _, err := w.out.Write(w.scratch[:4]); err != nil {
		return nil, err
	}

	if w.hashPool != nil {
		h := w.hashPool.getHash()
		binary.BigEndian.PutUint32(w.scratch[:], chunkSize)
		h.Write(w.scratch[:4])
		w.lastSum = h.Sum(nil)
		w.hashPool.putHash(h)
		if _, err := io.CopyN(w.out, bytes.NewReader(w.lastSum), int64(len(w.lastSum))); err != nil {
			return nil, err
		}
	}

	return w, nil
}

// flush writes a single buffer.
//
// +checklocks:w.mu
func (w *Writer) flush(c *chunk) error {
	// Prefix each chunk with a length; this allows the reader to safely
	// limit reads while buffering.
	l := uint32(c.compressed.Len())

	binary.BigEndian.PutUint32(w.scratch[:], l)
	if _, err := w.out.Write(w.scratch[:4]); err != nil {
		return err
	}

	// Write out to the stream.
	if _, err := io.CopyN(w.out, c.compressed, int64(c.compressed.Len())); err != nil {
		return err
	}

	if w.hashPool != nil {
		io.CopyN(c.h, bytes.NewReader(w.lastSum), int64(len(w.lastSum)))
		sum := c.h.Sum(nil)
		w.hashPool.putHash(c.h)
		c.h = nil
		if _, err := io.CopyN(w.out, bytes.NewReader(sum), int64(len(sum))); err != nil {
			return err
		}
		w.lastSum = sum
	}

	return nil
}

// Write implements io.Writer.Write.
//
// +checklocksexclude:w.mu
func (w *Writer) Write(p []byte) (done int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Did we close already?
	if w.closed {
		return 0, io.ErrUnexpectedEOF
	}
	if w.err != nil {
		return 0, w.err
	}
	defer func() {
		if err != nil {
			w.err = err
			// Finish all reads from p before the caller can reuse it.
			w.stop()
			// buf may be an unsubmitted inline slice of p. Do not return
			// caller-owned storage to bufPool or submit it on a later call.
			w.buf = nil
		}
	}()

	// See above; we need to track in the same way.
	var (
		pendingPre    = w.nextInput - w.nextOutput
		pendingInline = 0
	)
	callback := func(c *chunk) error {
		// schedule invokes this callback with w.mu held, but checklocks does
		// not propagate the lock state through the callback parameter.
		if pendingPre > 0 {
			pendingPre--
			err := w.flush(c) // +checklocksignore
			c.uncompressed.Reset()
			bufPool.Put(c.uncompressed)
			return err
		}
		if pendingInline > 0 {
			pendingInline--
			return w.flush(c) // +checklocksignore
		}
		panic("both pendingPre and pendingInline exhausted")
	}

	for done < len(p) {
		// Construct an inline buffer if we're doing an inline
		// encoding; see above regarding the bytes.MinRead constraint.
		inline := false
		if w.buf.Len() == 0 && len(p) >= done+int(w.chunkSize) && len(p) >= done+bytes.MinRead {
			bufPool.Put(w.buf) // Return to the pool; never scheduled.
			w.buf = bytes.NewBuffer(p[done : done+int(w.chunkSize)])
			inline = true
		}

		// Do we need to flush w.buf? Note that this case should be hit
		// immediately following the inline case above.
		left := int(w.chunkSize) - w.buf.Len()
		if left == 0 {
			if err := w.schedule(newChunk(nil, nil, nil, w.buf), callback); err != nil {
				return done, err
			}
			if inline {
				done += int(w.chunkSize)
				pendingInline++
			} else {
				pendingPre++
			}
			// Reset the buffer, since this has now been scheduled
			// for compression. Note that this may be trampled
			// immediately by the bufPool.Put(w.buf) above if the
			// next buffer happens to be inline, but that's okay.
			w.buf = bufPool.Get().(*bytes.Buffer)
			continue
		}

		// Read from p into w.buf.
		toWrite := len(p) - done
		if toWrite > left {
			toWrite = left
		}
		n, err := w.buf.Write(p[done : done+toWrite])
		done += n
		if err != nil {
			return done, err
		}
	}

	// Make sure that everything has been flushed, we can't return until
	// all the contents from p have been used.
	for pendingInline > 0 {
		if err := w.schedule(nil, func(c *chunk) error {
			if err := callback(c); err != nil {
				return err
			}
			// The flush was successful, return errNewBuffer here
			// to break from the loop and check the condition
			// again.
			return errNewBuffer
		}); err != errNewBuffer {
			return len(p), err
		}
	}

	return len(p), nil
}

// Close implements io.Closer.Close.
//
// +checklocksexclude:w.mu
func (w *Writer) Close() (err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Did we already close? After the call to Close, we always mark as
	// closed, regardless of whether the flush is successful.
	if w.closed {
		return io.ErrUnexpectedEOF
	}
	w.closed = true
	defer func() {
		w.stop()
		// Close the destination even if Write or the final flush failed,
		// but preserve the earlier error.
		if closer, ok := w.out.(io.Closer); ok {
			if closeErr := closer.Close(); err == nil {
				err = closeErr
			}
		}
	}()
	if w.err != nil {
		return w.err
	}

	// Schedule any remaining partial buffer; we pass w.flush directly here
	// because the final buffer is guaranteed to not be an inline buffer.
	if w.buf.Len() > 0 {
		if err := w.schedule(newChunk(nil, nil, nil, w.buf), w.flush); err != nil {
			return err
		}
	}

	// Flush all scheduled buffers; see above.
	if err := w.schedule(nil, w.flush); err != nil {
		return err
	}

	return nil
}
