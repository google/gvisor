// Copyright 2022 The gVisor Authors.
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

package buffer

import (
	"math/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewView(t *testing.T) {
	for sz := baseChunkSize; sz < maxChunkSize; sz <<= 1 {
		v := NewView(sz - 1)
		defer v.Release()

		if v.Capacity() != sz {
			t.Errorf("v.Capacity() = %d, want %d", v.Capacity(), sz)
		}
		if v.AvailableSize() != sz {
			t.Errorf("v.WriteSize() = %d, want %d", v.AvailableSize(), sz)
		}
		if v.Size() != 0 {
			t.Errorf("v.ReadSize() = %d, want %d", v.Size(), 0)
		}

		v1 := NewView(sz)
		defer v1.Release()

		if v1.Capacity() != sz {
			t.Errorf("v.Capacity() = %d, want %d", v.Capacity(), sz)
		}
		if v1.AvailableSize() != sz {
			t.Errorf("v.WriteSize() = %d, want %d", v.AvailableSize(), sz)
		}
		if v1.Size() != 0 {
			t.Errorf("v.ReadSize() = %d, want %d", v.Size(), 0)
		}
	}

	// Allocating from heap should produce a chunk with the exact size requested
	// instead of a chunk where the size is contingent on the pool it came from.
	viewSize := maxChunkSize + 1
	v := NewView(viewSize)
	defer v.Release()
	if v.Capacity() != viewSize {
		t.Errorf("v.Capacity() = %d, want %d", v.Capacity(), viewSize)
	}
}

func TestClone(t *testing.T) {
	orig := NewView(100)
	clone := orig.Clone()
	if orig.chunk != clone.chunk {
		t.Errorf("orig.Clone().chunk = %p, want %p", clone.chunk, orig.chunk)
	}
	if orig.chunk.refCount.Load() != 2 {
		t.Errorf("got orig.chunk.chunkRefs.Load() = %d, want 2", orig.chunk.refCount.Load())
	}
	orig.Release()
	if clone.chunk.refCount.Load() != 1 {
		t.Errorf("got clone.chunk.chunkRefs.Load() = %d, want 1", clone.chunk.refCount.Load())
	}
	clone.Release()
}

func TestWrite(t *testing.T) {
	for _, tc := range []struct {
		name      string
		view      *View
		initData  []byte
		writeSize int
	}{
		{
			name:      "empty view",
			view:      NewView(100),
			writeSize: 50,
		},
		{
			name:      "full view",
			view:      NewView(100),
			initData:  make([]byte, 100),
			writeSize: 50,
		},
		{
			name:      "full write to partially full view",
			view:      NewView(100),
			initData:  make([]byte, 20),
			writeSize: 50,
		},
		{
			name:      "partial write to partially full view",
			view:      NewView(100),
			initData:  make([]byte, 80),
			writeSize: 50,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.view.Write(tc.initData)
			defer tc.view.Release()
			origWriteSize := tc.view.AvailableSize()

			var orig []byte
			orig = append(orig, tc.view.AsSlice()...)
			toWrite := make([]byte, tc.writeSize)
			rand.Read(toWrite)

			n, _ := tc.view.Write(toWrite)

			if n > origWriteSize {
				t.Errorf("got tc.view.Write() = %d, want <=%d", n, origWriteSize)
			}
			if tc.writeSize > origWriteSize {
				toWrite = toWrite[:origWriteSize]
			}
			if tc.view.AvailableSize() != tc.view.Capacity()-(len(toWrite)+len(orig)) {
				t.Errorf("got tc.view.WriteSize() = %d, want %d", tc.view.AvailableSize(), tc.view.Capacity()-(len(toWrite)+len(orig)))
			}
			if !cmp.Equal(tc.view.AsSlice(), append(orig, toWrite...)) {
				t.Errorf("got tc.view.ReadSlice() = %d, want %d", tc.view.AsSlice(), toWrite)
			}
		})
	}
}

func TestWriteToCloned(t *testing.T) {
	orig := NewView(100)
	toWrite := make([]byte, 20)
	rand.Read(toWrite)
	orig.Write(toWrite)

	clone := orig.Clone()
	clone.Write(toWrite)

	if !cmp.Equal(orig.AsSlice(), toWrite) {
		t.Errorf("got orig.ReadSlice() = %v, want %v", orig.AsSlice(), toWrite)
	}

	toWrite = append(toWrite, toWrite...)
	if !cmp.Equal(clone.AsSlice(), toWrite) {
		t.Errorf("got clone.ReadSlice() = %v, want %v", clone.AsSlice(), toWrite)
	}
}

func TestWriteAt(t *testing.T) {
	size := 10
	off := 5
	v := NewViewSize(size)
	p := make([]byte, 20)
	rand.Read(p)
	orig := v.Clone()

	if n, _ := v.WriteAt(p, off); n != size-off {
		t.Errorf("got v.CopyIn()= %v, want %v", n, size-off)
	}
	if !cmp.Equal(v.AsSlice()[off:], p[:size-off]) {
		t.Errorf("got v.AsSlice()[off:] = %v, want %v", v.AsSlice()[off:], p[off:size])
	}
	if !cmp.Equal(v.AsSlice()[:off], orig.AsSlice()[:off]) {
		t.Errorf("got v.AsSlice()[:off] = %v, want %v", v.AsSlice()[:off], orig.AsSlice()[:off])
	}
}
