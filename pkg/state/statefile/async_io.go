// Copyright 2024 The gVisor Authors.
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

package statefile

import (
	"runtime"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sync"
)

type chunk struct {
	dst []byte
	off int64
}

// AsyncReader can be used to do reads asynchronously. It does not change the
// underlying file's offset.
type AsyncReader struct {
	// in is the backing file which contains all pages.
	in *fd.FD
	// off is the offset being read.
	off int64
	// q is the work queue.
	q chan chunk
	// err stores the latest IO error that occured during async read.
	err atomic.Pointer[error]
	// wg tracks all in flight work.
	wg sync.WaitGroup
}

// NewAsyncReader initializes a new AsyncReader.
func NewAsyncReader(in *fd.FD, off int64) *AsyncReader {
	workers := runtime.GOMAXPROCS(0)
	r := &AsyncReader{
		in:  in,
		off: off,
		q:   make(chan chunk, workers),
	}
	for i := 0; i < workers; i++ {
		go r.work()
	}
	return r
}

// ReadAsync schedules a read of len(p) bytes from current offset into p.
func (r *AsyncReader) ReadAsync(p []byte) {
	r.wg.Add(1)
	r.q <- chunk{off: r.off, dst: p}
	r.off += int64(len(p))
}

// Wait blocks until all in flight work is complete and then returns any IO
// errors that occurred since the last call to Wait().
func (r *AsyncReader) Wait() error {
	r.wg.Wait()
	if err := r.err.Swap(nil); err != nil {
		return *err
	}
	return nil
}

// Close calls Wait() and additionally cleans up all worker goroutines.
func (r *AsyncReader) Close() error {
	err := r.Wait()
	close(r.q)
	return err
}

func (r *AsyncReader) work() {
	for {
		c := <-r.q
		if c.dst == nil {
			return
		}
		if _, err := r.in.ReadAt(c.dst, c.off); err != nil {
			r.err.Store(&err)
		}
		r.wg.Done()
	}
}
