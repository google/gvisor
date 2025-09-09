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
	"math/bits"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

func TestIOWriterWrite(t *testing.T) {
	// Create random data.
	const chunkSize = 4096
	const dataLen = 1024 * chunkSize
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)

	// Write data using async writes.
	b := new(bytes.Buffer)
	w := NewIOWriter(b, chunkSize, 1 /* maxRanges */, 32 /* maxParallel */)
	wcu := cleanup.Make(func() { w.Close() })
	defer wcu.Clean()
	if w.NeedRegisterSourceFD() {
		t.Fatalf("IOWriter requires source FD registration")
	}
	ids := uint32(0)
	off := 0
	done := 0
	var cs []Completion
	for done < dataLen {
		for ids != ^uint32(0) && off < dataLen {
			id := bits.TrailingZeros32(^ids)
			ids |= uint32(1) << id
			w.AddWrite(id, nil, memmap.FileRange{}, data[off:off+chunkSize])
			off += chunkSize
		}
		cs, err := w.Wait(cs[:0], 1 /* minCompletions */)
		if err != nil {
			t.Fatalf("IOWriter.Wait failed: %v", err)
		}
		for _, c := range cs {
			if c.Err != nil {
				t.Fatalf("IOWriter returned completion with error: %v", c.Err)
			}
			if c.N != chunkSize {
				t.Fatalf("IOWriter returned completion of %d bytes, want %d", c.N, chunkSize)
			}
			ids &^= uint32(1) << c.ID
			done += chunkSize
		}
	}
	err := w.Close()
	wcu.Release()
	if err != nil {
		t.Fatalf("IOWriter.Close failed: %v", err)
	}

	if !bytes.Equal(data, b.Bytes()) {
		t.Errorf("Bytes differ")
	}
}

func TestIOWriterWritev(t *testing.T) {
	// Create random data.
	const chunkSize = 4096
	const dataLen = 1024 * chunkSize
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)

	// Write data using async writes.
	b := new(bytes.Buffer)
	w := NewIOWriter(b, chunkSize, 2 /* maxRanges */, 32 /* maxParallel */)
	wcu := cleanup.Make(func() { w.Close() })
	defer wcu.Clean()
	if w.NeedRegisterSourceFD() {
		t.Fatalf("IOWriter requires source FD registration")
	}
	ids := uint32(0)
	off := 0
	done := 0
	var cs []Completion
	for done < dataLen {
		for ids != ^uint32(0) && off < dataLen {
			id := bits.TrailingZeros32(^ids)
			ids |= uint32(1) << id
			iovecs := []unix.Iovec{
				{Base: &data[off], Len: chunkSize},
				{Base: &data[off+chunkSize], Len: chunkSize},
			}
			w.AddWritev(id, 2*chunkSize, nil, nil, iovecs)
			off += 2 * chunkSize
		}
		cs, err := w.Wait(cs[:0], 1 /* minCompletions */)
		if err != nil {
			t.Fatalf("IOWriter.Wait failed: %v", err)
		}
		for _, c := range cs {
			if c.Err != nil {
				t.Fatalf("IOWriter returned completion with error: %v", c.Err)
			}
			if c.N != 2*chunkSize {
				t.Fatalf("IOWriter returned completion of %d bytes, want %d", c.N, 2*chunkSize)
			}
			ids &^= uint32(1) << c.ID
			done += 2 * chunkSize
		}
	}
	err := w.Close()
	wcu.Release()
	if err != nil {
		t.Fatalf("IOWriter.Close failed: %v", err)
	}

	if !bytes.Equal(data, b.Bytes()) {
		t.Errorf("Bytes differ")
	}
}
