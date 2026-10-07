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
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/rand"
)

func TestNewView(t *testing.T) {
	for sz := baseChunkSize; sz < MaxChunkSize; sz <<= 1 {
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
	viewSize := MaxChunkSize + 1
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

func TestExternalViewCopyOnWrite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*View) error
		want   string
	}{
		{
			name: "WriteAt",
			modify: func(v *View) error {
				_, err := v.WriteAt([]byte("X"), 1)
				return err
			},
			want: "aXcd",
		},
		{
			name: "Write",
			modify: func(v *View) error {
				v.Reset()
				_, err := v.Write([]byte("XY"))
				return err
			},
			want: "XY",
		},
		{
			name: "ReadFrom",
			modify: func(v *View) error {
				v.Reset()
				_, err := v.ReadFrom(bytes.NewBufferString("XY"))
				return err
			},
			want: "XY",
		},
		{
			name: "Grow",
			modify: func(v *View) error {
				_, err := v.Write([]byte("e"))
				return err
			},
			want: "abcde",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storage := &externalTestStorage{data: []byte("abcd"), ready: true}
			original := NewViewWithExternalStorage(storage)
			owned := MakeWithView(original)
			defer owned.Release()
			clone := original.Clone()
			defer clone.Release()
			if got := original.BasePtr(); got != &storage.data[0] {
				t.Fatalf("BasePtr = %p, want %p", got, &storage.data[0])
			}
			if err := tc.modify(clone); err != nil {
				t.Fatal(err)
			}
			if got := string(original.AsSlice()); got != "abcd" {
				t.Fatalf("original bytes = %q, want abcd", got)
			}
			if got := string(clone.AsSlice()); got != tc.want {
				t.Fatalf("clone bytes = %q, want %q", got, tc.want)
			}
			if storage.releases != 0 {
				t.Fatalf("storage released during COW: %d", storage.releases)
			}
			owned.Release()
			if storage.releases != 1 {
				t.Fatalf("storage releases = %d, want 1", storage.releases)
			}
			if got := string(clone.AsSlice()); got != tc.want {
				t.Fatalf("clone after external release = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExternalViewSharedLifetime(t *testing.T) {
	storage := &externalTestStorage{data: bytes.Repeat([]byte("x"), MaxChunkSize), ready: true}
	v := NewViewWithExternalStorage(storage)
	clone := v.Clone()
	v.Release()
	if storage.releases != 0 {
		t.Fatalf("storage released while clone still exists: %d", storage.releases)
	}
	if got := clone.Size(); got != MaxChunkSize {
		t.Fatalf("clone size = %d, want %d", got, MaxChunkSize)
	}
	clone.Release()
	if storage.releases != 1 {
		t.Fatalf("storage releases = %d, want 1", storage.releases)
	}
}

func TestExternalViewInvalidLength(t *testing.T) {
	for _, size := range []int{0, MaxChunkSize + 1} {
		func() {
			storage := &externalTestStorage{data: make([]byte, size), ready: true}
			defer func() {
				if recover() == nil {
					t.Errorf("external storage length %d did not panic", size)
				}
				if storage.releases != 0 {
					t.Errorf("invalid storage length %d transferred ownership", size)
				}
				storage.Release()
			}()
			NewViewWithExternalStorage(storage).Release()
		}()
	}
}

func TestWrite(t *testing.T) {
	for _, tc := range []struct {
		name      string
		view      *View
		initSize  int
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
			initSize:  100,
			writeSize: 50,
		},
		{
			name:      "full write to partially full view",
			view:      NewView(100),
			initSize:  20,
			writeSize: 50,
		},
		{
			name:      "partial write to partially full view",
			view:      NewView(100),
			initSize:  80,
			writeSize: 50,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.view.Grow(tc.initSize)
			defer tc.view.Release()
			orig := append([]byte(nil), tc.view.AsSlice()...)
			toWrite := make([]byte, tc.writeSize)
			rand.Read(toWrite)

			n, err := tc.view.Write(toWrite)
			if err != nil {
				t.Errorf("Write failed: %s", err)
			}
			if n != tc.writeSize {
				t.Errorf("got n=%d, want %d", n, tc.writeSize)
			}
			if tc.view.Size() != len(orig)+tc.writeSize {
				t.Errorf("got Size()=%d, want %d", tc.view.Size(), len(orig)+tc.writeSize)
			}
			if !cmp.Equal(tc.view.AsSlice(), append(orig, toWrite...)) {
				t.Errorf("got tc.view.AsSlice() = %d, want %d", tc.view.AsSlice(), toWrite)
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

func TestWriteTo(t *testing.T) {
	writeToSize := 100
	v := NewViewSize(writeToSize)
	defer v.Release()

	w := bytes.NewBuffer(make([]byte, 100))

	n, err := v.WriteTo(w)
	if err != nil {
		t.Errorf("WriteTo failed: %s", err)
	}
	if n != int64(writeToSize) {
		t.Errorf("got n=%d, want 100", n)
	}
	if v.Size() != 0 {
		t.Errorf("got v.Size()=%d, want 0", v.Size())
	}
}

func TestReadFrom(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		view *View
	}{
		{
			name: "basic",
			data: []byte{1, 2, 3},
			view: NewView(10),
		},
		{
			name: "requires grow",
			data: []byte{4, 5, 6},
			view: NewViewSize(63),
		},
	} {
		defer tc.view.Release()
		clone := tc.view.Clone()
		defer clone.Release()
		r := bytes.NewReader(tc.data)

		n, err := tc.view.ReadFrom(r)

		if err != nil {
			t.Errorf("v.ReadFrom failed: %s", err)
		}
		if int(n) != len(tc.data) {
			t.Errorf("v.ReadFrom failed: want n=%d, got %d", len(tc.data), n)
		}
		if tc.view.Size() == clone.Size() {
			t.Errorf("expected clone.Size() != v.Size(), got match")
		}
		if !bytes.Equal(tc.view.AsSlice(), append(clone.AsSlice(), tc.data...)) {
			t.Errorf("v.ReadFrom failed: want %v, got %v", tc.data, tc.view.AsSlice())
		}
	}
}
