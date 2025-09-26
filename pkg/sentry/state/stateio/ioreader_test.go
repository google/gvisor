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
	"bytes"
	"io"
	"math/bits"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

func TestIOReaderRead(t *testing.T) {
	// Create random data.
	const chunkSize = 4096
	const dataLen = 1024 * chunkSize
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)

	// Read data using async reads.
	r := NewIOReader(bytes.NewReader(data), chunkSize, 1 /* maxRanges */, 32 /* maxParallel */)
	defer r.Close()
	if r.NeedRegisterDestinationFD() {
		t.Fatalf("IOReader requires destination FD registration")
	}
	buf := make([]byte, dataLen)
	ids := uint32(0)
	off := 0
	done := 0
	var cs []Completion
	for done < dataLen {
		for ids != ^uint32(0) && off < dataLen {
			id := bits.TrailingZeros32(^ids)
			ids |= uint32(1) << id
			r.AddRead(id, int64(off), nil, memmap.FileRange{}, buf[off:off+chunkSize])
			off += chunkSize
		}
		cs, err := r.Wait(cs[:0], 1 /* minCompletions */)
		if err != nil {
			t.Fatalf("IOReader.Wait failed: %v", err)
		}
		for _, c := range cs {
			if c.Err != nil && c.Err != io.EOF {
				t.Fatalf("IOReader returned completion with error: %v", c.Err)
			}
			if c.N != chunkSize {
				t.Fatalf("IOReader returned completion of %d bytes, want %d", c.N, chunkSize)
			}
			ids &^= uint32(1) << c.ID
			done += chunkSize
		}
	}

	if !bytes.Equal(data, buf) {
		t.Errorf("Bytes differ")
	}
}

func TestIOReaderReadv(t *testing.T) {
	// Create random data.
	const chunkSize = 4096
	const dataLen = 1024 * chunkSize
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)

	// Read data using async reads.
	r := NewIOReader(bytes.NewReader(data), chunkSize, 2 /* maxRanges */, 32 /* maxParallel */)
	defer r.Close()
	if r.NeedRegisterDestinationFD() {
		t.Fatalf("IOReader requires destination FD registration")
	}
	buf := make([]byte, dataLen)
	ids := uint32(0)
	off := 0
	done := 0
	var cs []Completion
	for done < dataLen {
		for ids != ^uint32(0) && off < dataLen {
			id := bits.TrailingZeros32(^ids)
			ids |= uint32(1) << id
			iovecs := []unix.Iovec{
				{Base: &buf[off], Len: chunkSize},
				{Base: &buf[off+chunkSize], Len: chunkSize},
			}
			r.AddReadv(id, int64(off), 2*chunkSize, nil, nil, iovecs)
			off += 2 * chunkSize
		}
		cs, err := r.Wait(cs[:0], 1 /* minCompletions */)
		if err != nil {
			t.Fatalf("IOReader.Wait failed: %v", err)
		}
		for _, c := range cs {
			if c.Err != nil && c.Err != io.EOF {
				t.Fatalf("IOReader returned completion with error: %v", c.Err)
			}
			if c.N != 2*chunkSize {
				t.Fatalf("IOReader returned completion of %d bytes, want %d", c.N, chunkSize)
			}
			ids &^= uint32(1) << c.ID
			done += 2 * chunkSize
		}
	}

	if !bytes.Equal(data, buf) {
		t.Errorf("Bytes differ")
	}
}
