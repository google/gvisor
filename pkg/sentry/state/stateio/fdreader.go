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
	q        *aio.GoQueue
	inflight []fdRead
	cs       []aio.Completion
}

type fdRead struct {
	off   int64
	done  uint64
	total uint64
	dst   LocalClientRanges
}

// NewFDReader returns a FDReader that reads from the given host
// file descriptor. It takes ownership of the file descriptor.
//
// Note that FDReader.MaxReadBytes()/MaxRanges() may be less than the specified
// maxReadBytes/maxRanges respectively, due to implementation constraints.
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
		inflight:     make([]fdRead, maxParallel),
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
	return len(r.inflight)
}

// AddRead implements AsyncReader.AddRead.
func (r *FDReader) AddRead(id int, off int64, _ DestinationFile, _ memmap.FileRange, dstMap []byte) {
	aio.Read(r.q, uint64(id), r.fd, off, dstMap)
	r.inflight[id] = fdRead{
		off:   off,
		total: uint64(len(dstMap)),
		dst:   LocalClientMapping(dstMap),
	}
}

// AddReadv implements AsyncReader.AddReadv.
func (r *FDReader) AddReadv(id int, off int64, total uint64, _ DestinationFile, _ []memmap.FileRange, dstMaps []unix.Iovec) {
	aio.Readv(r.q, uint64(id), r.fd, off, dstMaps)
	r.inflight[id] = fdRead{
		off:   off,
		total: total,
		dst:   LocalClientMappings(dstMaps),
	}
}

// Wait implements AsyncReader.Wait.
func (r *FDReader) Wait(cs []Completion, minCompletions int) ([]Completion, error) {
retry:
	numCompletions := 0
	aioCS, err := r.q.Wait(r.cs, minCompletions)
	for _, aioC := range aioCS {
		id := int(aioC.ID)
		inflight := &r.inflight[id]
		switch {
		case aioC.Result < 0:
			cs = append(cs, Completion{
				ID:  id,
				N:   inflight.done,
				Err: aioC.Err(),
			})
			numCompletions++
		case aioC.Result == 0:
			cs = append(cs, Completion{
				ID:  id,
				N:   inflight.done,
				Err: io.EOF,
			})
			numCompletions++
		default:
			n := uint64(aioC.Result)
			done := inflight.done + n
			if done == inflight.total {
				cs = append(cs, Completion{
					ID: id,
					N:  done,
				})
				numCompletions++
			} else {
				// Need to continue the read to get a full read or error.
				inflight.off += int64(n)
				inflight.done = done
				inflight.dst = inflight.dst.DropFirst(n)
				if inflight.dst.Mapping != nil {
					aio.Read(r.q, aioC.ID, r.fd, inflight.off, inflight.dst.Mapping)
				} else {
					aio.Readv(r.q, aioC.ID, r.fd, inflight.off, inflight.dst.Iovecs)
				}
				// Since r.q is an aio.GoQueue, aio.Read/Readv() =>
				// aio.GoQueue.Add() allows the enqueued read to execute
				// immediately, so we don't need to call r.q.Wait() again
				// unless we no longer have enough completions.
			}
		}
	}
	if numCompletions < minCompletions {
		minCompletions -= numCompletions
		goto retry
	}
	return cs, err
}
