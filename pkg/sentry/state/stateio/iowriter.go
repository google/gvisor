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

// IOWriter implements AsyncWriter by writing to an io.Writer using a
// goroutine. It is provided primarily for testing.
type IOWriter struct {
	NoRegisterClientFD

	dst           io.Writer
	maxWriteBytes uint64
	maxRanges     int
	subs          chan ioWriterSubmission
	cmps          chan Completion
	shutdown      chan struct{}
	workers       sync.WaitGroup
}

type ioWriterSubmission struct {
	id  int
	src LocalClientRanges
}

// NewIOWriter returns an IOWriter that writes to dst. It takes ownership of
// dst.
//
// Preconditions:
// - maxWriteBytes > 0.
// - maxRanges > 0.
// - maxParallel > 0.
func NewIOWriter(dst io.Writer, maxWriteBytes uint64, maxRanges, maxParallel int) *IOWriter {
	if maxWriteBytes <= 0 {
		panic("invalid maxWriteBytes")
	}
	if maxRanges <= 0 {
		panic("invalid maxRanges")
	}
	if maxParallel <= 0 {
		panic("invalid maxParallel")
	}
	w := &IOWriter{
		dst:           dst,
		maxWriteBytes: maxWriteBytes,
		maxRanges:     maxRanges,
		subs:          make(chan ioWriterSubmission, maxParallel),
		cmps:          make(chan Completion, maxParallel),
		shutdown:      make(chan struct{}),
	}
	w.workers.Add(1)
	go w.workerMain()
	return w
}

// Close implements AsyncWriter.Close.
func (w *IOWriter) Close() error {
	close(w.shutdown)
	w.workers.Wait()
	if c, ok := w.dst.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// MaxWriteBytes implements AsyncWriter.MaxWriteBytes.
func (w *IOWriter) MaxWriteBytes() uint64 {
	return w.maxWriteBytes
}

// MaxRanges implements AsyncWriter.MaxRanges.
func (w *IOWriter) MaxRanges() int {
	return w.maxRanges
}

// MaxParallel implements AsyncWriter.MaxParallel.
func (w *IOWriter) MaxParallel() int {
	return cap(w.subs)
}

// AddWrite implements AsyncWriter.AddWrite.
func (w *IOWriter) AddWrite(id int, _ SourceFile, _ memmap.FileRange, srcMap []byte) {
	w.subs <- ioWriterSubmission{
		id:  id,
		src: LocalClientMapping(srcMap),
	}
}

// AddWritev implements AsyncWriter.AddWritev.
func (w *IOWriter) AddWritev(id int, total uint64, _ SourceFile, _ []memmap.FileRange, srcMaps []unix.Iovec) {
	w.subs <- ioWriterSubmission{
		id:  id,
		src: LocalClientMappings(srcMaps),
	}
}

// Wait implements AsyncWriter.Wait.
func (w *IOWriter) Wait(cs []Completion, minCompletions int) ([]Completion, error) {
	return CompletionChanWait(w.cmps, cs, minCompletions)
}

// Reserve implements AsyncWriter.Reserve.
func (w *IOWriter) Reserve(n uint64) {
	// no-op
}

// Finalize implements AsyncWriter.Finalize.
func (w *IOWriter) Finalize() error {
	if c, ok := w.dst.(io.Closer); ok {
		// Arbitrary io.WriteClosers might not flush until Close.
		err := c.Close()
		// Don't close w.dst again in w.Close().
		w.dst = nil
		return err
	}
	return nil
}

func (w *IOWriter) workerMain() {
	defer w.workers.Done()
	for {
		select {
		case <-w.shutdown:
			return
		case sub := <-w.subs:
			var done uint64
			var doneErr error
			for _, src := range sub.src.Mappings {
				n, err := w.dst.Write(src)
				done += uint64(n)
				if err != nil {
					doneErr = err
					break
				}
			}
			w.cmps <- Completion{
				ID:  sub.id,
				N:   done,
				Err: doneErr,
			}
		}
	}
}
