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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/aio"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// FDReader implements AsyncReader for a host file descriptor.
type FDReader struct {
	NoRegisterClientFD

	fd           int32
	maxReadBytes uint32
	maxRanges    uint32
	// aio.GoQueue is preferred over aio.LinuxQueue for our use cases since it
	// can allocate and zero destination pages in parallel.
	q     *aio.GoQueue
	total []uint64
	cs    []aio.Completion
}

// NewFDReader returns a FDReader that reads from the given host
// file descriptor. It takes ownership of the file descriptor.
//
// Note that FDReader.MaxReadBytes() may be less than the specified
// maxReadBytes, and FDReader.MaxRanges() may be less than the specified
// maxRanges, due to implementation constraints.
//
// Preconditions:
// - maxReadBytes > 0.
// - maxRanges > 0.
// - maxParallel > 0.
func NewFDReader(fd int32, maxReadBytes uint64, maxRanges, maxParallel int) *FDReader {
	if maxReadBytes <= 0 {
		panic("invalid maxReadBytes")
	}
	if maxRanges <= 0 {
		panic("invalid maxRanges")
	}
	if maxParallel <= 0 {
		panic("invalid maxParallel")
	}
	return &FDReader{
		fd:           fd,
		maxReadBytes: uint32(min(maxReadBytes, uint64(linux.MAX_RW_COUNT))),
		maxRanges:    uint32(min(maxRanges, hostfd.MaxReadWriteIov)),
		q:            aio.NewGoQueue(maxParallel),
		total:        make([]uint64, maxParallel),
		cs:           make([]aio.Completion, 0, maxParallel),
	}
}

// Close implements AsyncReader.Close.
func (r *FDReader) Close() error {
	r.q.Destroy()
	return unix.Close(int(r.fd))
}

// MaxReadBytes implements AsyncReader.MaxReadBytes.
func (r *FDReader) MaxReadBytes() uint64 {
	return uint64(r.maxReadBytes)
}

// MaxRanges implements AsyncReader.MaxRanges.
func (r *FDReader) MaxRanges() int {
	return int(r.maxRanges)
}

// MaxParallel implements AsyncReader.MaxParallel.
func (r *FDReader) MaxParallel() int {
	// aio.GoQueue.Cap() returns the capacity of a channel. As of
	// https://go.dev/doc/go1.23#timer-changes, determining the capacity of a
	// channel requires a function call and some logic since timer channels are
	// special-cased, while determining the capacity of a slice still involves
	// only a memory load.
	return cap(r.cs)
}

// StartRead implements AsyncReader.StartRead.
func (r *FDReader) StartRead(id int, off int64, dstFile DestinationFile, dstFR memmap.FileRange, dstMap []byte) {
	r.total[id] = dstFR.Length()
	aio.Read(r.q, uint64(id), r.fd, off, dstMap)
}

// StartReadv implements AsyncReader.StartReadv.
func (r *FDReader) StartReadv(id int, off int64, total uint64, dstFile DestinationFile, dstFRs []memmap.FileRange, dstMaps []unix.Iovec) {
	r.total[id] = total
	aio.Readv(r.q, uint64(id), r.fd, off, dstMaps)
}

// Wait implements AsyncReader.Wait.
func (r *FDReader) Wait(cs []Completion, minCompletions int) ([]Completion, error) {
	aioCS, err := r.q.Wait(r.cs, minCompletions)
	for _, aioC := range aioCS {
		c := Completion{
			ID: int(aioC.ID),
		}
		switch {
		case aioC.Result < 0:
			c.Err = aioC.Err()
		case aioC.Result == 0:
			c.Err = io.EOF
		default:
			c.N = uint64(aioC.Result)
			if c.N < r.total[c.ID] {
				// Assume that this was due to EOF.
				c.Err = io.EOF
			}
		}
		cs = append(cs, c)
	}
	return cs, err
}
