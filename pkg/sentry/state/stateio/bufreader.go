// Copyright 2025 The gVisor Authors.
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

package stateio

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// BufReader implements io.ReadCloser for an AsyncReader by reading into a
// buffering memfd.
type BufReader struct {
	// The BufReader's buffer is logically divided into numChunks chunks of
	// equal length. Each chunk is filled from the AsyncReader as soon as it
	// becomes empty.

	// buf is the whole buffer. buf[bufStart:bufEnd] is the unread part of the
	// current chunk. bufErr is the error to be returned at the end of the
	// current chunk.
	buf      []byte
	bufStart int
	bufEnd   int
	bufErr   error

	// If waitErr is non-nil, it is the error returned by ar.Wait().
	waitErr error

	// curChunk is the index of the current chunk.
	curChunk int

	// numChunks is the total number of chunks in the buffer. numChunks is
	// immutable.
	numChunks int

	// chunksRefillable is the number of chunks preceding curChunk that should
	// be read.
	chunksRefillable int

	// chunkLen is the size of each chunk in bytes. chunkLen is immutable.
	chunkLen int

	// chunks holds read completion state for each chunk. The chunks slice
	// header is immutable.
	chunks []bufReaderChunk

	// stopReading is set after any call to ar.Wait() returns a non-nil
	// Completion.Err. stopReading is primarily used to avoid issuing useless
	// reads after reaching EOF.
	stopReading bool

	// refillOffset is the offset in ar at which the next chunk to be refilled
	// should be read.
	refillOffset int64

	// ar is the data source. ar is immutable.
	ar AsyncReader

	// df represents the file backing the buffer. df is immutable.
	df DestinationFile

	// cs is a slice of completions whose storage is reused by all calls to
	// ar.Wait(). The cs slice header is immutable.
	cs []Completion
}

type bufReaderChunk struct {
	readyLen int
	err      error
}

// NewBufReader returns a BufReader that reads from ar. If size is positive, it
// is the maximum size of the BufReader's buffer in bytes; otherwise, the
// maximum size is unspecified. NewBufReader takes ownership of
// ar, even if it returns a non-nil error.
func NewBufReader(ar AsyncReader, size int) (*BufReader, error) {
	bytesPerChunk, numChunks := getBufReadWriterParams(ar.MaxReadBytes(), ar.MaxParallel(), size)
	bufSize := bytesPerChunk * numChunks
	memfd, buf, err := CreateMappedMemoryFD("stateio.BufReader", bufSize)
	if err != nil {
		ar.Close()
		return nil, err
	}
	defer unix.Close(int(memfd))
	df, err := ar.RegisterDestinationFD(memfd, uint64(bufSize), nil)
	if err != nil {
		unix.Munmap(buf)
		ar.Close()
		return nil, fmt.Errorf("failed to register memfd of size %d bytes: %w", bufSize, err)
	}

	return &BufReader{
		buf:              buf,
		chunksRefillable: numChunks,
		numChunks:        numChunks,
		chunkLen:         bytesPerChunk,
		chunks:           make([]bufReaderChunk, numChunks),
		ar:               ar,
		df:               df,
		cs:               make([]Completion, 0, numChunks),
	}, nil
}

// Close implements io.Closer.Close.
func (r *BufReader) Close() error {
	return errors.Join(r.ar.Close(), unix.Munmap(r.buf))
}

// Read implements io.Reader.Read.
func (r *BufReader) Read(dst []byte) (int, error) {
	done := 0
	for {
		for {
			if r.bufStart < r.bufEnd {
				// Copy from current chunk until either chunk or dst are empty.
				n := copy(dst, r.buf[r.bufStart:r.bufEnd])
				dst = dst[n:]
				r.bufStart += n
				done += n
				if r.bufStart < r.bufEnd {
					// Copying ended before the end of the chunk, so dst must now be
					// empty.
					if r.waitErr != nil {
						// Don't return r.waitErr yet since there might be
						// unconsumed buffers for later reads to read from.
						return done, nil
					}
					break
				}
				// Advance to the next chunk.
				r.chunksRefillable++
				r.curChunk++
				if r.curChunk >= r.numChunks {
					r.curChunk = 0
				}
			}
			// Return error from reading the last chunk.
			if r.bufErr != nil {
				return done, r.bufErr
			}
			chunk := &r.chunks[r.curChunk]
			r.bufStart = r.chunkLen * r.curChunk
			if chunk.readyLen == 0 && chunk.err == nil {
				// Wait for this chunk to become ready. Set r.bufEnd equal to
				// r.bufStart for now so that the above check correctly detects
				// that chunk is empty.
				r.bufEnd = r.bufStart
				if r.waitErr != nil {
					return done, r.waitErr
				}
				break
			}
			r.bufEnd = r.bufStart + chunk.readyLen
			r.bufErr = chunk.err
			*chunk = bufReaderChunk{}
		}
		// Invariant: r.waitErr == nil.
		// Enqueue reads to fill empty chunks.
		enqueuedAny := false
		if !r.stopReading && r.chunksRefillable != 0 {
			chunkToRefill := r.curChunk - r.chunksRefillable
			if chunkToRefill < 0 {
				chunkToRefill += r.numChunks
			}
			for range r.chunksRefillable {
				chunkStart := r.chunkLen * chunkToRefill
				chunkEnd := chunkStart + r.chunkLen
				r.ar.AddRead(chunkToRefill, r.refillOffset, r.df, memmap.FileRange{uint64(chunkStart), uint64(chunkEnd)}, r.buf[chunkStart:chunkEnd])
				chunkToRefill++
				if chunkToRefill >= r.numChunks {
					chunkToRefill = 0
				}
				r.refillOffset += int64(r.chunkLen)
			}
			r.chunksRefillable = 0
			enqueuedAny = true
		}
		// Submit reads, and wait for the current chunk to complete if dst still
		// needs data.
		if len(dst) == 0 {
			if enqueuedAny {
				r.wait(0)
			}
			return done, nil
		}
		chunk := &r.chunks[r.curChunk]
		for {
			r.wait(1)
			if chunk.readyLen != 0 || chunk.err != nil {
				// r.bufStart was set correctly when this chunk became current.
				r.bufEnd = r.bufStart + chunk.readyLen
				r.bufErr = chunk.err
				*chunk = bufReaderChunk{}
				break
			}
			if r.waitErr != nil {
				return done, r.waitErr
			}
		}
	}
}

func (r *BufReader) wait(minCompletions int) {
	cs, err := r.ar.Wait(r.cs, minCompletions)
	for _, c := range cs {
		r.chunks[c.ID] = bufReaderChunk{
			readyLen: int(c.N),
			err:      c.Err,
		}
		if c.Err != nil {
			r.stopReading = true
		}
	}
	r.waitErr = err
}

func getBufReadWriterParams(maxIOBytes64 uint64, maxParallel, maxSize int) (bytesPerChunk, numChunks int) {
	// Arbitrary limits:
	const (
		maxChunks     = 32
		maxChunkBytes = 32 << 20
	)
	maxIOBytes := int(min(maxIOBytes64, maxChunkBytes))
	maxParallel = min(maxParallel, maxChunks)
	if maxSize <= 0 {
		return maxIOBytes, maxParallel
	}
	// Can we accomodate at least two reads/writes of size maxIOBytes? We don't
	// want to set the read/write size below maxIOBytes unless necessary, and
	// two is the minimum number of chunks required to have any amount of
	// async prefetching/writeback.
	if maxIOBytes*2 <= maxSize {
		return maxIOBytes, min(maxSize/maxIOBytes, maxParallel)
	}
	if maxSize > 1 && maxParallel > 1 {
		return maxSize / 2, 2
	}
	// maxSize == 1 || maxParallel == 1:
	return min(maxIOBytes, maxSize), 1
}
