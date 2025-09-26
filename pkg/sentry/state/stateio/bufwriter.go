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
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// BufWriter implements io.WriteCloser for an AsyncWriter by writing from a
// buffering memfd.
type BufWriter struct {
	// The BufWriter's buffer is logically divided into numChunks chunks of
	// equal length. Each chunk is filled by Write and then written to the
	// AsyncWriter as soon as it becomes full.

	// buf is the whole buffer. buf[bufStart:bufEnd] is the empty part of the
	// current chunk.
	buf      []byte
	bufStart int
	bufEnd   int

	// If err is non-nil, it is the error that has terminated writing.
	err error

	// curChunk is the index of the current chunk.
	curChunk int

	// numChunks is the total number of chunks in the buffer. numChunks is
	// immutable.
	numChunks int

	// chunksFlushable is the number of chunks preceding curChunk that should
	// be written.
	chunksFlushable int

	// chunksInflight is the number of inflight writes in aw.
	chunksInflight int

	// chunkLen is the size of each chunk in bytes. chunkLen is immutable.
	chunkLen int

	// chunks holds availability for each chunk. The chunks slice header is
	// immutable.
	chunks []bufWriterChunk

	// aw is the data sink. ar is immutable.
	aw AsyncWriter

	// sf represents the file backing the buffer. sf is immutable.
	sf SourceFile

	// cs is a slice of completions whose storage is reused by all calls to
	// aw.Wait(). The cs slice header is immutable.
	cs []Completion
}

type bufWriterChunk struct {
	// busy is true if the chunk contains any amount of buffered data.
	busy bool
}

// NewBufWriter returns a BufWriter that writes to aw. If size is positive, it
// is the maximum size of the BufWriter's buffer in bytes; otherwise, the
// maximum size is unspecified. NewBufWriter takes ownership of
// aw, even if it returns a non-nil error.
func NewBufWriter(aw AsyncWriter, size int) (*BufWriter, error) {
	bytesPerChunk, numChunks := getBufReadWriterParams(aw.MaxWriteBytes(), aw.MaxParallel(), size)
	bufSize := bytesPerChunk * numChunks
	memfd, buf, err := CreateMappedMemoryFD("stateio.BufWriter", bufSize)
	if err != nil {
		aw.Close()
		return nil, err
	}
	defer unix.Close(int(memfd))
	sf, err := aw.RegisterSourceFD(memfd, uint64(bufSize), nil)
	if err != nil {
		unix.Munmap(buf)
		aw.Close()
		return nil, fmt.Errorf("failed to register memfd of size %d bytes: %w", bufSize, err)
	}

	w := &BufWriter{
		buf:       buf,
		bufEnd:    bytesPerChunk,
		numChunks: numChunks,
		chunkLen:  bytesPerChunk,
		chunks:    make([]bufWriterChunk, numChunks),
		aw:        aw,
		sf:        sf,
		cs:        make([]Completion, 0, numChunks),
	}
	w.chunks[0].busy = true
	return w, nil
}

// Close implements io.Closer.Close.
func (w *BufWriter) Close() error {
	if w.err != nil {
		// w.err was already returned by the last call to Write; we don't need
		// to return it again.
		return errors.Join(w.aw.Close(), unix.Munmap(w.buf))
	}

	// Flush current chunk if non-empty.
	if chunkStart := w.chunkLen * w.curChunk; chunkStart != w.bufStart {
		w.aw.AddWrite(w.curChunk, w.sf, memmap.FileRange{uint64(chunkStart), uint64(w.bufStart)}, w.buf[chunkStart:w.bufStart])
		w.chunksInflight++
	}

	// Wait for all chunks to finish flushing.
	var waitErr error
	if w.chunksInflight != 0 {
		waitErr = w.wait(w.chunksInflight)
	}

	var finalizeErr error
	if waitErr == nil {
		finalizeErr = w.aw.Finalize()
	}

	// Callers will probably treat io.WriteCloser.Close() errors as fatal due
	// to the existence of buffered writes. Only return errors that indicate
	// write failure, and log non-fatal ones.
	if err := w.aw.Close(); err != nil {
		log.Infof("stateio.BufWriter: stateio.AsyncWriter.Close failed: %v", err)
	}
	if err := unix.Munmap(w.buf); err != nil {
		log.Infof("stateio.BufWriter: unix.Munmap failed: %v", err)
	}
	return errors.Join(waitErr, finalizeErr)
}

// Write implements io.Writer.Write.
func (w *BufWriter) Write(src []byte) (int, error) {
	// If w.aw.Wait() or any previous write has returned an error, success is
	// impossible (because we can't write out any more chunks), so return
	// immediately.
	if w.err != nil {
		return 0, w.err
	}

	done := 0
	for {
		for {
			if w.bufStart < w.bufEnd {
				// Copy to current chunk until either chunk is full or src is
				// empty.
				n := copy(w.buf[w.bufStart:w.bufEnd], src)
				src = src[n:]
				w.bufStart += n
				done += n
				if w.bufStart < w.bufEnd {
					// Copying ended before the end of the chunk, so src must
					// now be empty.
					break
				}
				// Advance to the next chunk.
				w.chunksFlushable++
				w.curChunk++
				if w.curChunk >= w.numChunks {
					w.curChunk = 0
				}
			}
			chunk := &w.chunks[w.curChunk]
			w.bufStart = w.chunkLen * w.curChunk
			if chunk.busy {
				// Wait for this chunk to become available. Set w.bufEnd to be
				// w.bufStart so that the chunk is detected as unusable above,
				// but also detected as empty by Close().
				w.bufEnd = w.bufStart
				break
			}
			w.bufEnd = w.bufStart + w.chunkLen
			chunk.busy = true
		}
		// Enqueue writes to flush full chunks.
		enqueuedAny := false
		if w.chunksFlushable != 0 {
			chunkToFlush := w.curChunk - w.chunksFlushable
			if chunkToFlush < 0 {
				chunkToFlush += w.numChunks
			}
			for range w.chunksFlushable {
				chunkStart := w.chunkLen * chunkToFlush
				chunkEnd := chunkStart + w.chunkLen
				w.aw.AddWrite(chunkToFlush, w.sf, memmap.FileRange{uint64(chunkStart), uint64(chunkEnd)}, w.buf[chunkStart:chunkEnd])
				w.chunksInflight++
				chunkToFlush++
				if chunkToFlush >= w.numChunks {
					chunkToFlush = 0
				}
			}
			w.chunksFlushable = 0
			enqueuedAny = true
		}
		// Submit writes, and wait for the current chunk to complete if src
		// still needs buffer space.
		if len(src) == 0 {
			if enqueuedAny {
				if err := w.wait(0); err != nil {
					w.err = err
					return done, err
				}
			}
			return done, nil
		}
		chunk := &w.chunks[w.curChunk]
		for {
			if err := w.wait(1); err != nil {
				w.err = err
				return done, err
			}
			if !chunk.busy {
				w.bufEnd = w.bufStart + w.chunkLen
				chunk.busy = true
				break
			}
		}
	}
}

func (w *BufWriter) wait(minCompletions int) error {
	cs, err := w.aw.Wait(w.cs, minCompletions)
	w.chunksInflight -= len(cs)
	for _, c := range cs {
		if c.Err != nil {
			return c.Err
		}
		w.chunks[c.ID].busy = false
	}
	if err != nil {
		return fmt.Errorf("stateio.AsyncWriter.Wait failed: %w", err)
	}
	return nil
}
