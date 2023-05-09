// Copyright 2021 The gVisor Authors.
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

package bufferv2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

func BenchmarkReadAt(b *testing.B) {
	b.ReportAllocs()
	var buf Buffer
	buf.Append(NewView(100))
	defer buf.Release()

	bytes := make([]byte, 10)
	for i := 0; i < b.N; i++ {
		buf.ReadAt(bytes, 0)
	}
}

func BenchmarkWriteRead(b *testing.B) {
	b.ReportAllocs()
	var buf Buffer
	defer buf.Release()
	sz := 1000
	rbuf := bytes.NewBuffer(make([]byte, sz))
	for i := 0; i < b.N; i++ {
		buf.Append(NewView(sz))
		rbuf.Reset()
		buf.ReadToWriter(rbuf, int64(sz))
	}
}

func fillAppend(b *Buffer, data []byte) {
	b.Append(NewViewWithData(data))
}

func fillAppendEnd(b *Buffer, data []byte) {
	b.GrowTo(baseChunkSize-1, false)
	b.Append(NewViewWithData(data))
	b.TrimFront(baseChunkSize - 1)
}

func fillWriteFromReader(b *Buffer, data []byte) {
	buf := bytes.NewBuffer(data)
	b.WriteFromReader(buf, int64(len(data)))
}

func fillWriteFromReaderEnd(b *Buffer, data []byte) {
	b.GrowTo(baseChunkSize-1, false)
	buf := bytes.NewBuffer(data)
	b.WriteFromReader(buf, int64(len(data)))
	b.TrimFront(baseChunkSize - 1)
}

var fillFuncs = map[string]func(*Buffer, []byte){
	"append":             fillAppend,
	"appendEnd":          fillAppendEnd,
	"writeFromReader":    fillWriteFromReader,
	"writeFromReaderEnd": fillWriteFromReaderEnd,
}

func testReadAt(t *testing.T, b *Buffer, offset int64, n int, wantStr string, wantErr error) {
	t.Helper()
	d := make([]byte, n)
	n, err := b.ReadAt(d, offset)
	if n != len(wantStr) {
		t.Errorf("got %d, want %d", n, len(wantStr))
	}
	if err != wantErr {
		t.Errorf("got err %v, want %v", err, wantErr)
	}
	if !bytes.Equal(d[:n], []byte(wantStr)) {
		t.Errorf("got %q, want %q", string(d[:n]), wantStr)
	}
}

func TestBuffer(t *testing.T) {
	testCases := []struct {
		name   string
		input  string
		output string
		op     func(*testing.T, *Buffer)
	}{
		// Preconditions.
		{
			name:   "truncate-check",
			input:  "hello",
			output: "hello", // Not touched.
			op: func(t *testing.T, b *Buffer) {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("Truncate(-1) did not panic")
					}
				}()
				b.Truncate(-1)
			},
		},
		{
			name:   "growto-check",
			input:  "hello",
			output: "hello", // Not touched.
			op: func(t *testing.T, b *Buffer) {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("GrowTo(-1) did not panic")
					}
				}()
				b.GrowTo(-1, false)
			},
		},
		{
			name:   "advance-check",
			input:  "hello",
			output: "", // Consumed.
			op: func(t *testing.T, b *Buffer) {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("advanceRead(Size()+1) did not panic")
					}
				}()
				b.advanceRead(b.Size() + 1)
			},
		},

		// Prepend.
		{
			name:   "prepend",
			input:  "world",
			output: "hello world",
			op: func(t *testing.T, b *Buffer) {
				b.Prepend(NewViewWithData([]byte("hello ")))
			},
		},
		{
			name:   "prepend-backfill-full",
			input:  "hello world",
			output: "jello world",
			op: func(t *testing.T, b *Buffer) {
				b.TrimFront(1)
				b.Prepend(NewViewWithData([]byte("j")))
			},
		},
		{
			name:   "prepend-backfill-under",
			input:  "hello world",
			output: "hola world",
			op: func(t *testing.T, b *Buffer) {
				b.TrimFront(5)
				b.Prepend(NewViewWithData([]byte("hola")))
			},
		},
		{
			name:   "prepend-backfill-over",
			input:  "hello world",
			output: "smello world",
			op: func(t *testing.T, b *Buffer) {
				b.TrimFront(1)
				b.Prepend(NewViewWithData([]byte("sm")))
			},
		},
		{
			name:   "prepend-fill",
			input:  strings.Repeat("1", baseChunkSize-1),
			output: "0" + strings.Repeat("1", baseChunkSize-1),
			op: func(t *testing.T, b *Buffer) {
				b.Prepend(NewViewWithData([]byte("0")))
			},
		},
		{
			name:   "prepend-overflow",
			input:  strings.Repeat("1", baseChunkSize),
			output: "0" + strings.Repeat("1", baseChunkSize),
			op: func(t *testing.T, b *Buffer) {
				b.Prepend(NewViewWithData([]byte("0")))
			},
		},
		{
			name:   "prepend-multiple-buffers",
			input:  strings.Repeat("1", baseChunkSize-1),
			output: strings.Repeat("0", baseChunkSize*3) + strings.Repeat("1", baseChunkSize-1),
			op: func(t *testing.T, b *Buffer) {
				b.Prepend(NewViewWithData([]byte(strings.Repeat("0", baseChunkSize))))
				b.Prepend(NewViewWithData([]byte(strings.Repeat("0", baseChunkSize))))
				b.Prepend(NewViewWithData([]byte(strings.Repeat("0", baseChunkSize))))
			},
		},

		// Append and write.
		{
			name:   "append",
			input:  "hello",
			output: "hello world",
			op: func(t *testing.T, b *Buffer) {
				b.Append(NewViewWithData([]byte(" world")))
			},
		},
		{
			name:   "append-fill",
			input:  strings.Repeat("1", baseChunkSize-1),
			output: strings.Repeat("1", baseChunkSize-1) + "0",
			op: func(t *testing.T, b *Buffer) {
				b.Append(NewViewWithData([]byte("0")))
			},
		},
		{
			name:   "append-overflow",
			input:  strings.Repeat("1", baseChunkSize),
			output: strings.Repeat("1", baseChunkSize) + "0",
			op: func(t *testing.T, b *Buffer) {
				b.Append(NewViewWithData([]byte("0")))
			},
		},
		{
			name:   "append-multiple-views",
			input:  strings.Repeat("1", baseChunkSize-1),
			output: strings.Repeat("1", baseChunkSize-1) + strings.Repeat("0", baseChunkSize*3),
			op: func(t *testing.T, b *Buffer) {
				b.Append(NewViewWithData([]byte(strings.Repeat("0", baseChunkSize))))
				b.Append(NewViewWithData([]byte(strings.Repeat("0", baseChunkSize))))
				b.Append(NewViewWithData([]byte(strings.Repeat("0", baseChunkSize))))
			},
		},

		// AppendOwned.
		{
			name:   "append-owned",
			input:  "hello",
			output: "hello world",
			op: func(t *testing.T, b *Buffer) {
				v := NewViewWithData([]byte("Xworld"))
				// Appending to a buffer that has extra references means this will
				// degrade into an "appendOwned" for the chunk being added.
				c := b.Clone()
				defer c.Release()
				b.Append(v)
				v.chunk.data[0] = ' '
			},
		},

		// Truncate.
		{
			name:   "truncate",
			input:  "hello world",
			output: "hello",
			op: func(t *testing.T, b *Buffer) {
				b.Truncate(5)
			},
		},
		{
			name:   "truncate-noop",
			input:  "hello world",
			output: "hello world",
			op: func(t *testing.T, b *Buffer) {
				b.Truncate(b.Size() + 1)
			},
		},
		{
			name:   "truncate-multiple-buffers",
			input:  strings.Repeat("1", baseChunkSize),
			output: strings.Repeat("1", baseChunkSize*2-1),
			op: func(t *testing.T, b *Buffer) {
				b.Append(NewViewWithData([]byte(strings.Repeat("1", baseChunkSize))))
				b.Truncate(baseChunkSize*2 - 1)
			},
		},
		{
			name:   "truncate-multiple-buffers-to-one",
			input:  strings.Repeat("1", baseChunkSize),
			output: "11111",
			op: func(t *testing.T, b *Buffer) {
				b.Append(NewViewWithData([]byte(strings.Repeat("1", baseChunkSize))))
				b.Truncate(5)
			},
		},

		// TrimFront.
		{
			name:   "trim",
			input:  "hello world",
			output: "world",
			op: func(t *testing.T, b *Buffer) {
				b.TrimFront(6)
			},
		},
		{
			name:   "trim-too-large",
			input:  "hello world",
			output: "",
			op: func(t *testing.T, b *Buffer) {
				b.TrimFront(b.Size() + 1)
			},
		},
		{
			name:   "trim-multiple-buffers",
			input:  strings.Repeat("1", baseChunkSize),
			output: strings.Repeat("1", baseChunkSize*2-1),
			op: func(t *testing.T, b *Buffer) {
				b.Append(NewViewWithData([]byte(strings.Repeat("1", baseChunkSize))))
				b.TrimFront(1)
			},
		},
		{
			name:   "trim-multiple-buffers-to-one-buffer",
			input:  strings.Repeat("1", baseChunkSize),
			output: "1",
			op: func(t *testing.T, b *Buffer) {
				b.Append(NewViewWithData([]byte(strings.Repeat("1", baseChunkSize))))
				b.TrimFront(baseChunkSize*2 - 1)
			},
		},

		// GrowTo.
		{
			name:   "growto",
			input:  "hello world",
			output: "hello world",
			op: func(t *testing.T, b *Buffer) {
				b.GrowTo(1, true)
			},
		},
		{
			name:   "growto-from-zero",
			output: strings.Repeat("\x00", 1024),
			op: func(t *testing.T, b *Buffer) {
				b.GrowTo(1024, true)
			},
		},
		{
			name:   "growto-from-non-zero",
			input:  strings.Repeat("1", baseChunkSize),
			output: strings.Repeat("1", baseChunkSize) + strings.Repeat("\x00", baseChunkSize),
			op: func(t *testing.T, b *Buffer) {
				b.GrowTo(baseChunkSize*2, true)
			},
		},

		// Clone.
		{
			name:   "clone",
			input:  "hello",
			output: "hello",
			op: func(t *testing.T, b *Buffer) {
				other := b.Clone()
				bs := other.Flatten()
				want := []byte("hello")
				if !bytes.Equal(bs, want) {
					t.Errorf("expected %v, got %v", want, bs)
				}
			},
		},
		{
			name:   "copy-large",
			input:  strings.Repeat("1", baseChunkSize+1),
			output: strings.Repeat("1", baseChunkSize+1),
			op: func(t *testing.T, b *Buffer) {
				other := b.Clone()
				bs := other.Flatten()
				want := []byte(strings.Repeat("1", baseChunkSize+1))
				if !bytes.Equal(bs, want) {
					t.Errorf("expected %v, got %v", want, bs)
				}
			},
		},

		// Merge.
		{
			name:   "merge",
			input:  "hello",
			output: "hello world",
			op: func(t *testing.T, b *Buffer) {
				var other Buffer
				other.Append(NewViewWithData([]byte(" world")))
				b.Merge(&other)
				if sz := other.Size(); sz != 0 {
					t.Errorf("expected 0, got %d", sz)
				}
			},
		},
		{
			name:   "merge-large",
			input:  strings.Repeat("1", baseChunkSize+1),
			output: strings.Repeat("1", baseChunkSize+1) + strings.Repeat("0", baseChunkSize+1),
			op: func(t *testing.T, b *Buffer) {
				var other Buffer
				other.Append(NewViewWithData(([]byte(strings.Repeat("0", baseChunkSize+1)))))
				b.Merge(&other)
				if sz := other.Size(); sz != 0 {
					t.Errorf("expected 0, got %d", sz)
				}
			},
		},

		// ReadAt.
		{
			name:   "readat",
			input:  "hello",
			output: "hello",
			op:     func(t *testing.T, b *Buffer) { testReadAt(t, b, 0, 6, "hello", io.EOF) },
		},
		{
			name:   "readat-long",
			input:  "hello",
			output: "hello",
			op:     func(t *testing.T, b *Buffer) { testReadAt(t, b, 0, 8, "hello", io.EOF) },
		},
		{
			name:   "readat-short",
			input:  "hello",
			output: "hello",
			op:     func(t *testing.T, b *Buffer) { testReadAt(t, b, 0, 3, "hel", nil) },
		},
		{
			name:   "readat-offset",
			input:  "hello",
			output: "hello",
			op:     func(t *testing.T, b *Buffer) { testReadAt(t, b, 2, 3, "llo", io.EOF) },
		},
		{
			name:   "readat-long-offset",
			input:  "hello",
			output: "hello",
			op:     func(t *testing.T, b *Buffer) { testReadAt(t, b, 2, 8, "llo", io.EOF) },
		},
		{
			name:   "readat-short-offset",
			input:  "hello",
			output: "hello",
			op:     func(t *testing.T, b *Buffer) { testReadAt(t, b, 2, 2, "ll", nil) },
		},
		{
			name:   "readat-skip-all",
			input:  "hello",
			output: "hello",
			op:     func(t *testing.T, b *Buffer) { testReadAt(t, b, baseChunkSize+1, 1, "", io.EOF) },
		},
		{
			name:   "readat-second-view",
			input:  strings.Repeat("0", baseChunkSize+1) + "12",
			output: strings.Repeat("0", baseChunkSize+1) + "12",
			op:     func(t *testing.T, b *Buffer) { testReadAt(t, b, baseChunkSize+1, 1, "1", nil) },
		},
		{
			name:   "readat-second-buffer-end",
			input:  strings.Repeat("0", baseChunkSize+1) + "12",
			output: strings.Repeat("0", baseChunkSize+1) + "12",
			op:     func(t *testing.T, b *Buffer) { testReadAt(t, b, baseChunkSize+1, 2, "12", io.EOF) },
		},
	}

	for _, tc := range testCases {
		for fillName, fn := range fillFuncs {
			t.Run(fillName+"/"+tc.name, func(t *testing.T) {
				// Construct & fill the view.
				var buf Buffer
				fn(&buf, []byte(tc.input))

				// Run the operation.
				if tc.op != nil {
					tc.op(t, &buf)
				}

				// Flatten and validate.
				out := buf.Flatten()
				if !bytes.Equal([]byte(tc.output), out) {
					t.Errorf("expected %q, got %q", tc.output, string(out))
				}

				// Ensure the size is correct.
				if len(out) != int(buf.Size()) {
					t.Errorf("size is wrong: expected %d, got %d", len(out), buf.Size())
				}

				// Calculate contents via apply.
				var appliedOut []byte
				buf.Apply(func(v *View) {
					appliedOut = append(appliedOut, v.AsSlice()...)
				})
				if len(appliedOut) != len(out) {
					t.Errorf("expected %d, got %d", len(out), len(appliedOut))
				}
				if !bytes.Equal(appliedOut, out) {
					t.Errorf("expected %v, got %v", out, appliedOut)
				}

				// Calculate contents via ReadToWriter.
				var b bytes.Buffer
				n, err := buf.ReadToWriter(&b, int64(len(out)))
				if n != int64(len(out)) {
					t.Errorf("expected %d, got %d", len(out), n)
				}
				if err != nil {
					t.Errorf("expected nil, got %v", err)
				}
				if !bytes.Equal(b.Bytes(), out) {
					t.Errorf("expected %v, got %v", out, b.Bytes())
				}
			})
		}
	}
}

func TestBufferPullUp(t *testing.T) {
	for _, tc := range []struct {
		desc   string
		inputs []string
		offset int
		length int
		output string
		failed bool
		// lengths is the lengths of each buffer node after the pull up.
		lengths []int
	}{
		{
			desc: "whole empty view",
		},
		{
			desc:    "zero pull",
			inputs:  []string{"hello", " world"},
			lengths: []int{5, 6},
		},
		{
			desc:    "whole view",
			inputs:  []string{"hello", " world"},
			offset:  0,
			length:  11,
			output:  "hello world",
			lengths: []int{11},
		},
		{
			desc:    "middle to end aligned",
			inputs:  []string{"0123", "45678", "9abcd"},
			offset:  4,
			length:  10,
			output:  "456789abcd",
			lengths: []int{4, 10},
		},
		{
			desc:    "middle to end unaligned",
			inputs:  []string{"0123", "45678", "9abcd"},
			offset:  6,
			length:  8,
			output:  "6789abcd",
			lengths: []int{4, 10},
		},
		{
			desc:    "middle aligned",
			inputs:  []string{"0123", "45678", "9abcd", "efgh"},
			offset:  6,
			length:  5,
			output:  "6789a",
			lengths: []int{4, 10, 4},
		},

		// Failed cases.
		{
			desc:   "empty view - length too long",
			offset: 0,
			length: 1,
			failed: true,
		},
		{
			desc:   "empty view - offset too large",
			offset: 1,
			length: 1,
			failed: true,
		},
		{
			desc:    "length too long",
			inputs:  []string{"0123", "45678", "9abcd"},
			offset:  4,
			length:  100,
			failed:  true,
			lengths: []int{4, 5, 5},
		},
		{
			desc:    "offset too large",
			inputs:  []string{"0123", "45678", "9abcd"},
			offset:  100,
			length:  1,
			failed:  true,
			lengths: []int{4, 5, 5},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			var b Buffer
			defer b.Release()
			for _, s := range tc.inputs {
				v := NewViewWithData([]byte(s))
				b.appendOwned(v)
			}

			got, gotOk := b.PullUp(tc.offset, tc.length)
			want, wantOk := []byte(tc.output), !tc.failed
			if gotOk == wantOk && got.Size() == 0 && len(want) == 0 {
				return
			}
			if gotOk != wantOk || !bytes.Equal(got.AsSlice(), want) {
				t.Errorf("v.PullUp(%d, %d) = %q, %t; %q, %t", tc.offset, tc.length, got.AsSlice(), gotOk, want, wantOk)
			}

			var gotLengths []int
			for v := b.data.Front(); v != nil; v = v.Next() {
				gotLengths = append(gotLengths, v.Size())
			}
			if !reflect.DeepEqual(gotLengths, tc.lengths) {
				t.Errorf("lengths = %v; want %v", gotLengths, tc.lengths)
			}
		})
	}
}

func TestReadFromLargeWriter(t *testing.T) {
	writeSize := int64(1 << 20)
	largeWriter := bytes.NewBuffer(make([]byte, writeSize))
	b := Buffer{}
	// Expect this write to be buffered into several MaxChunkSize sized views.
	n, err := b.WriteFromReader(largeWriter, writeSize)
	if err != nil {
		t.Fatalf("b.WriteFromReader() failed: want err=nil, got %v", err)
	}
	if n != writeSize {
		t.Errorf("got b.WriteFromReader()=%d, want %d", n, writeSize)
	}
	nChunks := int(writeSize / MaxChunkSize)
	if b.data.Len() != nChunks {
		t.Errorf("b.WriteFromReader() failed, got b.data.Len()=%d, want %d", b.data.Len(), nChunks)
	}
}

func TestRead(t *testing.T) {
	readStrings := []string{"abcdef", "123456", "ghijkl"}
	totalSize := len(readStrings) * len(readStrings[0])
	for readSz := 0; readSz < totalSize+1; readSz++ {
		b := Buffer{}
		for _, s := range readStrings {
			v := NewViewWithData([]byte(s))
			b.appendOwned(v)
		}
		orig := b.Clone()
		orig.Truncate(int64(readSz))
		p := make([]byte, readSz)
		_, err := b.read(p)
		if err != nil {
			t.Fatalf("Read([]byte(%d)) failed: %v", readSz, err)
		}
		if !bytes.Equal(p, orig.Flatten()) {
			t.Errorf("Read([]byte(%d)) failed, want p=%v, got %v", readSz, orig.Flatten(), p)
		}
		if int(b.Size()) != totalSize-readSz {
			t.Errorf("Read([]byte(%d)) failed, want b.Size()=%v, got %v", readSz, totalSize-readSz, b.Size())
		}
	}
}

func TestReadByte(t *testing.T) {
	readString := "abcdef123456ghijkl"
	b := Buffer{}
	nViews := 3
	for i := 0; i < nViews; i++ {
		vLen := len(readString) / nViews
		v := NewViewWithData([]byte(readString[i*vLen : (i+1)*vLen]))
		b.appendOwned(v)
	}
	for i := 0; i < len(readString); i++ {
		orig := readString[i]
		bt, err := b.readByte()
		if err != nil {
			t.Fatalf("readByte() failed: %v", err)
		}
		if bt != orig {
			t.Errorf("readByte() failed, want %v, got %v", orig, bt)
		}
		if int(b.Size()) != len(readString[i+1:]) {
			t.Errorf("readByte() failed, want b.Size()=%v, got %v", len(readString[i+1:]), b.Size())
		}
	}
}

func TestPullUpModifiedViews(t *testing.T) {
	var b Buffer
	defer b.Release()
	for _, s := range []string{"abcdef", "123456", "ghijkl"} {
		v := NewViewWithData([]byte(s))
		v.TrimFront(3)
		b.appendOwned(v)
	}

	v, ok := b.PullUp(3, 3)
	if !ok {
		t.Errorf("PullUp failed: want ok=true, got ok=false")
	}
	want := []byte("456")
	if !bytes.Equal(v.AsSlice(), want) {
		t.Errorf("PullUp failed: want %v, got %v", want, v.AsSlice())
	}
}

func TestBufferClone(t *testing.T) {
	const (
		originalSize  = 90
		bytesToDelete = 30
	)
	b := MakeWithData(bytes.Repeat([]byte{originalSize}, originalSize))
	clonedB := b.Clone()
	b.TrimFront(bytesToDelete)

	if got, want := int(b.Size()), originalSize-bytesToDelete; got != want {
		t.Errorf("original buffer was not changed: size expected = %d, got = %d", want, got)
	}
	if got := clonedB.Size(); got != originalSize {
		t.Errorf("cloned buffer should not be modified: expected size = %d, got = %d", originalSize, got)
	}
}

func TestBufferSubApply(t *testing.T) {
	var b Buffer
	defer b.Release()
	b.appendOwned(NewViewWithData([]byte("0123")))
	b.appendOwned(NewViewWithData([]byte("45678")))
	b.appendOwned(NewViewWithData([]byte("9abcd")))
	data := []byte("0123456789abcd")

	for i := 0; i <= len(data); i++ {
		for j := i; j <= len(data); j++ {
			t.Run(fmt.Sprintf("SubApply(%d,%d)", i, j), func(t *testing.T) {
				var got []byte
				b.SubApply(i, j-i, func(v *View) {
					got = append(got, v.AsSlice()...)
				})
				if want := data[i:j]; !bytes.Equal(got, want) {
					t.Errorf("got = %q; want %q", got, want)
				}
			})
		}
	}
}

func doSaveAndLoad(t *testing.T, toSave, toLoad *Buffer) {
	t.Helper()
	var buf bytes.Buffer
	ctx := context.Background()
	if _, err := state.Save(ctx, &buf, toSave); err != nil {
		t.Fatal("state.Save:", err)
	}
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), toLoad); err != nil {
		t.Fatal("state.Load:", err)
	}
}

func TestSaveRestoreBufferEmpty(t *testing.T) {
	var toSave Buffer
	var b Buffer
	doSaveAndLoad(t, &toSave, &b)

	if got := b.Flatten(); len(got) != 0 {
		t.Errorf("v.Flatten() = %x, want []", got)
	}
}

func TestSaveRestoreBuffer(t *testing.T) {
	// Create data that fits  slots.
	data := bytes.Join([][]byte{
		bytes.Repeat([]byte{1, 2}, baseChunkSize),
	}, nil)

	var toSave Buffer
	toSave.appendOwned(NewViewWithData(data))

	var b Buffer
	doSaveAndLoad(t, &toSave, &b)

	// Next available slot at index 3; 0-2 slot are used.
	if got := b.Flatten(); !bytes.Equal(got, data) {
		t.Errorf("v.Flatten() = %x, want %x", got, data)
	}
}

func TestRangeIntersect(t *testing.T) {
	for _, tc := range []struct {
		desc       string
		x, y, want Range
	}{
		{
			desc: "empty intersects empty",
		},
		{
			desc: "empty intersection",
			x:    Range{end: 10},
			y:    Range{begin: 10, end: 20},
		},
		{
			desc: "some intersection",
			x:    Range{begin: 5, end: 20},
			y:    Range{end: 10},
			want: Range{begin: 5, end: 10},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			if got := tc.x.Intersect(tc.y); got != tc.want {
				t.Errorf("(%#v).Intersect(%#v) = %#v; want %#v", tc.x, tc.y, got, tc.want)
			}
			if got := tc.y.Intersect(tc.x); got != tc.want {
				t.Errorf("(%#v).Intersect(%#v) = %#v; want %#v", tc.y, tc.x, got, tc.want)
			}
		})
	}
}

func TestRangeOffset(t *testing.T) {
	for _, tc := range []struct {
		input  Range
		offset int
		output Range
	}{
		{
			input:  Range{},
			offset: 0,
			output: Range{},
		},
		{
			input:  Range{},
			offset: -1,
			output: Range{begin: -1, end: -1},
		},
		{
			input:  Range{begin: 10, end: 20},
			offset: -1,
			output: Range{begin: 9, end: 19},
		},
		{
			input:  Range{begin: 10, end: 20},
			offset: 2,
			output: Range{begin: 12, end: 22},
		},
	} {
		if got := tc.input.Offset(tc.offset); got != tc.output {
			t.Errorf("(%#v).Offset(%d) = %#v, want %#v", tc.input, tc.offset, got, tc.output)
		}
	}
}

func TestRangeLen(t *testing.T) {
	for _, tc := range []struct {
		r    Range
		want int
	}{
		{r: Range{}, want: 0},
		{r: Range{begin: 1, end: 1}, want: 0},
		{r: Range{begin: -1, end: -1}, want: 0},
		{r: Range{end: 10}, want: 10},
		{r: Range{begin: 5, end: 10}, want: 5},
	} {
		if got := tc.r.Len(); got != tc.want {
			t.Errorf("(%#v).Len() = %d, want %d", tc.r, got, tc.want)
		}
	}
}

func TestChecksum(t *testing.T) {
	data := make([]byte, 100)
	rand.Read(data)

	b := MakeWithData(data[:30])
	b.appendOwned(NewViewWithData(data[30:70]))
	b.appendOwned(NewViewWithData(data[70:]))

	for offset := 0; offset < 100; offset++ {
		var cs checksum.Checksumer
		cs.Add(data[offset:])
		dataChecksum := cs.Checksum()
		bufChecksum := b.Checksum(offset)

		if dataChecksum != bufChecksum {
			t.Errorf("(%#v).Checksum(%d) = %d, want %d", b, offset, bufChecksum, dataChecksum)
		}
	}
}
