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
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sync"
)

// IOReader implements AsyncReader by reading from an io.ReaderAt using a
// goroutine pool. It is provided primarily for testing.
type IOReader struct {
	NoRegisterClientFD

	src          io.ReaderAt
	maxReadBytes uint64
	maxRanges    int
	subs         chan ioReaderSubmission
	cmps         chan Completion
	shutdown     chan struct{}
	workers      sync.WaitGroup
}

type ioReaderSubmission struct {
	id  int
	off int64
	dst LocalClientRanges
}

// NewIOReader returns a IOReader that reads from src. It takes ownership
// of src.
//
// Preconditions:
// - maxReadBytes > 0.
// - maxRanges > 0.
// - maxParallel > 0.
func NewIOReader(src io.ReaderAt, maxReadBytes uint64, maxRanges, maxParallel int) *IOReader {
	if maxReadBytes <= 0 {
		panic("invalid maxReadBytes")
	}
	if maxRanges <= 0 {
		panic("invalid maxRanges")
	}
	if maxParallel <= 0 {
		panic("invalid maxParallel")
	}
	r := &IOReader{
		src:          src,
		maxReadBytes: maxReadBytes,
		maxRanges:    maxRanges,
		subs:         make(chan ioReaderSubmission, maxParallel),
		cmps:         make(chan Completion, maxParallel),
		shutdown:     make(chan struct{}),
	}
	r.workers.Add(maxParallel)
	for range maxParallel {
		go r.workerMain()
	}
	return r
}

// Close implements AsyncReader.Close.
func (r *IOReader) Close() error {
	close(r.shutdown)
	r.workers.Wait()
	if c, ok := r.src.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// MaxReadBytes implements AsyncReader.MaxReadBytes.
func (r *IOReader) MaxReadBytes() uint64 {
	return r.maxReadBytes
}

// MaxRanges implements AsyncReader.MaxRanges.
func (r *IOReader) MaxRanges() int {
	return r.maxRanges
}

// MaxParallel implements AsyncReader.MaxParallel.
func (r *IOReader) MaxParallel() int {
	return cap(r.subs)
}

// AddRead implements AsyncReader.AddRead.
func (r *IOReader) AddRead(id int, off int64, _ DestinationFile, _ memmap.FileRange, dstMap []byte) {
	r.subs <- ioReaderSubmission{
		id:  id,
		off: off,
		dst: LocalClientMapping(dstMap),
	}
}

// AddReadv implements AsyncReader.AddReadv.
func (r *IOReader) AddReadv(id int, off int64, total uint64, _ DestinationFile, _ []memmap.FileRange, dstMaps []unix.Iovec) {
	r.subs <- ioReaderSubmission{
		id:  id,
		off: off,
		dst: LocalClientMappings(dstMaps),
	}
}

// Wait implements AsyncReader.Wait.
func (r *IOReader) Wait(cs []Completion, minCompletions int) ([]Completion, error) {
	return CompletionChanWait(r.cmps, cs, minCompletions)
}

func (r *IOReader) workerMain() {
	defer r.workers.Done()
	for {
		select {
		case <-r.shutdown:
			return
		case sub := <-r.subs:
			var done uint64
			var doneErr error
			for _, dst := range sub.dst.Mappings {
				n, err := r.src.ReadAt(dst, sub.off)
				sub.off += int64(n)
				done += uint64(n)
				if err != nil {
					doneErr = err
					break
				}
			}
			r.cmps <- Completion{
				ID:  sub.id,
				N:   done,
				Err: doneErr,
			}
		}
	}
}
