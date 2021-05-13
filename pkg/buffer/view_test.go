// Copyright 2020 The gVisor Authors.
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
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
)

const bufferSize = defaultBufferSize

func fillAppend(v *View, data []byte) {
	v.Append(data)
}

func fillAppendEnd(v *View, data []byte) {
	v.Grow(bufferSize-1, false)
	v.Append(data)
	v.TrimFront(bufferSize - 1)
}

func fillWriteFromReader(v *View, data []byte) {
	b := bytes.NewBuffer(data)
	v.WriteFromReader(b, int64(len(data)))
}

func fillWriteFromReaderEnd(v *View, data []byte) {
	v.Grow(bufferSize-1, false)
	b := bytes.NewBuffer(data)
	v.WriteFromReader(b, int64(len(data)))
	v.TrimFront(bufferSize - 1)
}

var fillFuncs = map[string]func(*View, []byte){
	"append":             fillAppend,
	"appendEnd":          fillAppendEnd,
	"writeFromReader":    fillWriteFromReader,
	"writeFromReaderEnd": fillWriteFromReaderEnd,
}

func BenchmarkReadAt(b *testing.B) {
	b.ReportAllocs()
	var v View
	v.Append(make([]byte, 100))

	buf := make([]byte, 10)
	for i := 0; i < b.N; i++ {
		v.ReadAt(buf, 0)
	}
}

func BenchmarkWriteRead(b *testing.B) {
	b.ReportAllocs()
	var v View
	sz := 1000
	wbuf := make([]byte, sz)
	rbuf := bytes.NewBuffer(make([]byte, sz))
	for i := 0; i < b.N; i++ {
		v.Append(wbuf)
		rbuf.Reset()
		v.ReadToWriter(rbuf, int64(sz))
	}
}

func testReadAt(t *testing.T, v *View, offset int64, n int, wantStr string, wantErr error) {
	t.Helper()
	d := make([]byte, n)
	n, err := v.ReadAt(d, offset)
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

func TestView(t *testing.T) {
	testCases := []struct {
		name   string
		input  string
		output string
		op     func(*testing.T, *View)
	}{
		// Preconditions.
		{
			name:   "truncate-check",
			input:  "hello",
			output: "hello", // Not touched.
			op: func(t *testing.T, v *View) {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("Truncate(-1) did not panic")
					}
				}()
				v.Truncate(-1)
			},
		},
		{
			name:   "grow-check",
			input:  "hello",
			output: "hello", // Not touched.
			op: func(t *testing.T, v *View) {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("Grow(-1) did not panic")
					}
				}()
				v.Grow(-1, false)
			},
		},
		{
			name:   "advance-check",
			input:  "hello",
			output: "", // Consumed.
			op: func(t *testing.T, v *View) {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("advanceRead(Size()+1) did not panic")
					}
				}()
				v.advanceRead(v.Size() + 1)
			},
		},

		// Prepend.
		{
			name:   "prepend",
			input:  "world",
			output: "hello world",
			op: func(t *testing.T, v *View) {
				v.Prepend([]byte("hello "))
			},
		},
		{
			name:   "prepend-backfill-full",
			input:  "hello world",
			output: "jello world",
			op: func(t *testing.T, v *View) {
				v.TrimFront(1)
				v.Prepend([]byte("j"))
			},
		},
		{
			name:   "prepend-backfill-under",
			input:  "hello world",
			output: "hola world",
			op: func(t *testing.T, v *View) {
				v.TrimFront(5)
				v.Prepend([]byte("hola"))
			},
		},
		{
			name:   "prepend-backfill-over",
			input:  "hello world",
			output: "smello world",
			op: func(t *testing.T, v *View) {
				v.TrimFront(1)
				v.Prepend([]byte("sm"))
			},
		},
		{
			name:   "prepend-fill",
			input:  strings.Repeat("1", bufferSize-1),
			output: "0" + strings.Repeat("1", bufferSize-1),
			op: func(t *testing.T, v *View) {
				v.Prepend([]byte("0"))
			},
		},
		{
			name:   "prepend-overflow",
			input:  strings.Repeat("1", bufferSize),
			output: "0" + strings.Repeat("1", bufferSize),
			op: func(t *testing.T, v *View) {
				v.Prepend([]byte("0"))
			},
		},
		{
			name:   "prepend-multiple-buffers",
			input:  strings.Repeat("1", bufferSize-1),
			output: strings.Repeat("0", bufferSize*3) + strings.Repeat("1", bufferSize-1),
			op: func(t *testing.T, v *View) {
				v.Prepend([]byte(strings.Repeat("0", bufferSize*3)))
			},
		},

		// Append and write.
		{
			name:   "append",
			input:  "hello",
			output: "hello world",
			op: func(t *testing.T, v *View) {
				v.Append([]byte(" world"))
			},
		},
		{
			name:   "append-fill",
			input:  strings.Repeat("1", bufferSize-1),
			output: strings.Repeat("1", bufferSize-1) + "0",
			op: func(t *testing.T, v *View) {
				v.Append([]byte("0"))
			},
		},
		{
			name:   "append-overflow",
			input:  strings.Repeat("1", bufferSize),
			output: strings.Repeat("1", bufferSize) + "0",
			op: func(t *testing.T, v *View) {
				v.Append([]byte("0"))
			},
		},
		{
			name:   "append-multiple-buffers",
			input:  strings.Repeat("1", bufferSize-1),
			output: strings.Repeat("1", bufferSize-1) + strings.Repeat("0", bufferSize*3),
			op: func(t *testing.T, v *View) {
				v.Append([]byte(strings.Repeat("0", bufferSize*3)))
			},
		},

		// AppendOwned.
		{
			name:   "append-owned",
			input:  "hello",
			output: "hello world",
			op: func(t *testing.T, v *View) {
				b := []byte("Xworld")
				v.AppendOwned(b)
				b[0] = ' '
			},
		},

		// Truncate.
		{
			name:   "truncate",
			input:  "hello world",
			output: "hello",
			op: func(t *testing.T, v *View) {
				v.Truncate(5)
			},
		},
		{
			name:   "truncate-noop",
			input:  "hello world",
			output: "hello world",
			op: func(t *testing.T, v *View) {
				v.Truncate(v.Size() + 1)
			},
		},
		{
			name:   "truncate-multiple-buffers",
			input:  strings.Repeat("1", bufferSize*2),
			output: strings.Repeat("1", bufferSize*2-1),
			op: func(t *testing.T, v *View) {
				v.Truncate(bufferSize*2 - 1)
			},
		},
		{
			name:   "truncate-multiple-buffers-to-one",
			input:  strings.Repeat("1", bufferSize*2),
			output: "11111",
			op: func(t *testing.T, v *View) {
				v.Truncate(5)
			},
		},

		// TrimFront.
		{
			name:   "trim",
			input:  "hello world",
			output: "world",
			op: func(t *testing.T, v *View) {
				v.TrimFront(6)
			},
		},
		{
			name:   "trim-too-large",
			input:  "hello world",
			output: "",
			op: func(t *testing.T, v *View) {
				v.TrimFront(v.Size() + 1)
			},
		},
		{
			name:   "trim-multiple-buffers",
			input:  strings.Repeat("1", bufferSize*2),
			output: strings.Repeat("1", bufferSize*2-1),
			op: func(t *testing.T, v *View) {
				v.TrimFront(1)
			},
		},
		{
			name:   "trim-multiple-buffers-to-one-buffer",
			input:  strings.Repeat("1", bufferSize*2),
			output: "1",
			op: func(t *testing.T, v *View) {
				v.TrimFront(bufferSize*2 - 1)
			},
		},

		// Grow.
		{
			name:   "grow",
			input:  "hello world",
			output: "hello world",
			op: func(t *testing.T, v *View) {
				v.Grow(1, true)
			},
		},
		{
			name:   "grow-from-zero",
			output: strings.Repeat("\x00", 1024),
			op: func(t *testing.T, v *View) {
				v.Grow(1024, true)
			},
		},
		{
			name:   "grow-from-non-zero",
			input:  strings.Repeat("1", bufferSize),
			output: strings.Repeat("1", bufferSize) + strings.Repeat("\x00", bufferSize),
			op: func(t *testing.T, v *View) {
				v.Grow(bufferSize*2, true)
			},
		},

		// Copy.
		{
			name:   "copy",
			input:  "hello",
			output: "hello",
			op: func(t *testing.T, v *View) {
				other := v.Copy()
				bs := other.Flatten()
				want := []byte("hello")
				if !bytes.Equal(bs, want) {
					t.Errorf("expected %v, got %v", want, bs)
				}
			},
		},
		{
			name:   "copy-large",
			input:  strings.Repeat("1", bufferSize+1),
			output: strings.Repeat("1", bufferSize+1),
			op: func(t *testing.T, v *View) {
				other := v.Copy()
				bs := other.Flatten()
				want := []byte(strings.Repeat("1", bufferSize+1))
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
			op: func(t *testing.T, v *View) {
				var other View
				other.Append([]byte(" world"))
				v.Merge(&other)
				if sz := other.Size(); sz != 0 {
					t.Errorf("expected 0, got %d", sz)
				}
			},
		},
		{
			name:   "merge-large",
			input:  strings.Repeat("1", bufferSize+1),
			output: strings.Repeat("1", bufferSize+1) + strings.Repeat("0", bufferSize+1),
			op: func(t *testing.T, v *View) {
				var other View
				other.Append([]byte(strings.Repeat("0", bufferSize+1)))
				v.Merge(&other)
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
			op:     func(t *testing.T, v *View) { testReadAt(t, v, 0, 6, "hello", io.EOF) },
		},
		{
			name:   "readat-long",
			input:  "hello",
			output: "hello",
			op:     func(t *testing.T, v *View) { testReadAt(t, v, 0, 8, "hello", io.EOF) },
		},
		{
			name:   "readat-short",
			input:  "hello",
			output: "hello",
			op:     func(t *testing.T, v *View) { testReadAt(t, v, 0, 3, "hel", nil) },
		},
		{
			name:   "readat-offset",
			input:  "hello",
			output: "hello",
			op:     func(t *testing.T, v *View) { testReadAt(t, v, 2, 3, "llo", io.EOF) },
		},
		{
			name:   "readat-long-offset",
			input:  "hello",
			output: "hello",
			op:     func(t *testing.T, v *View) { testReadAt(t, v, 2, 8, "llo", io.EOF) },
		},
		{
			name:   "readat-short-offset",
			input:  "hello",
			output: "hello",
			op:     func(t *testing.T, v *View) { testReadAt(t, v, 2, 2, "ll", nil) },
		},
		{
			name:   "readat-skip-all",
			input:  "hello",
			output: "hello",
			op:     func(t *testing.T, v *View) { testReadAt(t, v, bufferSize+1, 1, "", io.EOF) },
		},
		{
			name:   "readat-second-buffer",
			input:  strings.Repeat("0", bufferSize+1) + "12",
			output: strings.Repeat("0", bufferSize+1) + "12",
			op:     func(t *testing.T, v *View) { testReadAt(t, v, bufferSize+1, 1, "1", nil) },
		},
		{
			name:   "readat-second-buffer-end",
			input:  strings.Repeat("0", bufferSize+1) + "12",
			output: strings.Repeat("0", bufferSize+1) + "12",
			op:     func(t *testing.T, v *View) { testReadAt(t, v, bufferSize+1, 2, "12", io.EOF) },
		},
	}

	for _, tc := range testCases {
		for fillName, fn := range fillFuncs {
			t.Run(fillName+"/"+tc.name, func(t *testing.T) {
				// Construct & fill the view.
				var view View
				fn(&view, []byte(tc.input))

				// Run the operation.
				if tc.op != nil {
					tc.op(t, &view)
				}

				// Flatten and validate.
				out := view.Flatten()
				if !bytes.Equal([]byte(tc.output), out) {
					t.Errorf("expected %q, got %q", tc.output, string(out))
				}

				// Ensure the size is correct.
				if len(out) != int(view.Size()) {
					t.Errorf("size is wrong: expected %d, got %d", len(out), view.Size())
				}

				// Calculate contents via apply.
				var appliedOut []byte
				view.Apply(func(b []byte) {
					appliedOut = append(appliedOut, b...)
				})
				if len(appliedOut) != len(out) {
					t.Errorf("expected %d, got %d", len(out), len(appliedOut))
				}
				if !bytes.Equal(appliedOut, out) {
					t.Errorf("expected %v, got %v", out, appliedOut)
				}

				// Calculate contents via ReadToWriter.
				var b bytes.Buffer
				n, err := view.ReadToWriter(&b, int64(len(out)))
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

func TestViewPullUp(t *testing.T) {
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
			var v View
			for _, s := range tc.inputs {
				v.AppendOwned([]byte(s))
			}

			got, gotOk := v.PullUp(tc.offset, tc.length)
			want, wantOk := []byte(tc.output), !tc.failed
			if gotOk != wantOk || !bytes.Equal(got, want) {
				t.Errorf("v.PullUp(%d, %d) = %q, %t; %q, %t", tc.offset, tc.length, got, gotOk, want, wantOk)
			}

			var gotLengths []int
			for buf := v.data.Front(); buf != nil; buf = buf.Next() {
				gotLengths = append(gotLengths, buf.ReadSize())
			}
			if !reflect.DeepEqual(gotLengths, tc.lengths) {
				t.Errorf("lengths = %v; want %v", gotLengths, tc.lengths)
			}
		})
	}
}

func TestViewRemove(t *testing.T) {
	// Success cases
	for _, tc := range []struct {
		desc string
		// before is the contents for each buffer node initially.
		before []string
		// after is the contents for each buffer node after removal.
		after  []string
		offset int
		length int
	}{
		{
			desc: "empty view",
		},
		{
			desc:   "nothing removed",
			before: []string{"hello", " world"},
			after:  []string{"hello", " world"},
		},
		{
			desc:   "whole view",
			before: []string{"hello", " world"},
			offset: 0,
			length: 11,
		},
		{
			desc:   "beginning to middle aligned",
			before: []string{"0123", "45678", "9abcd"},
			after:  []string{"9abcd"},
			offset: 0,
			length: 9,
		},
		{
			desc:   "beginning to middle unaligned",
			before: []string{"0123", "45678", "9abcd"},
			after:  []string{"678", "9abcd"},
			offset: 0,
			length: 6,
		},
		{
			desc:   "middle to end aligned",
			before: []string{"0123", "45678", "9abcd"},
			after:  []string{"0123"},
			offset: 4,
			length: 10,
		},
		{
			desc:   "middle to end unaligned",
			before: []string{"0123", "45678", "9abcd"},
			after:  []string{"0123", "45"},
			offset: 6,
			length: 8,
		},
		{
			desc:   "middle aligned",
			before: []string{"0123", "45678", "9abcd"},
			after:  []string{"0123", "9abcd"},
			offset: 4,
			length: 5,
		},
		{
			desc:   "middle unaligned",
			before: []string{"0123", "45678", "9abcd"},
			after:  []string{"0123", "4578", "9abcd"},
			offset: 6,
			length: 1,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			var v View
			for _, s := range tc.before {
				v.AppendOwned([]byte(s))
			}

			if ok := v.Remove(tc.offset, tc.length); !ok {
				t.Errorf("v.Remove(%d, %d) = false, want true", tc.offset, tc.length)
			}

			var got []string
			for buf := v.data.Front(); buf != nil; buf = buf.Next() {
				got = append(got, string(buf.ReadSlice()))
			}
			if !reflect.DeepEqual(got, tc.after) {
				t.Errorf("after = %v; want %v", got, tc.after)
			}
		})
	}

	// Failure cases
	for _, tc := range []struct {
		desc string
		// before is the contents for each buffer node initially.
		before []string
		offset int
		length int
	}{
		{
			desc:   "offset out-of-range",
			before: []string{"hello", " world"},
			offset: -1,
			length: 3,
		},
		{
			desc:   "length too long",
			before: []string{"hello", " world"},
			offset: 0,
			length: 12,
		},
		{
			desc:   "length too long with positive offset",
			before: []string{"hello", " world"},
			offset: 3,
			length: 9,
		},
		{
			desc:   "length negative",
			before: []string{"hello", " world"},
			offset: 0,
			length: -1,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			var v View
			for _, s := range tc.before {
				v.AppendOwned([]byte(s))
			}
			if ok := v.Remove(tc.offset, tc.length); ok {
				t.Errorf("v.Remove(%d, %d) = true, want false", tc.offset, tc.length)
			}
		})
	}
}

func TestViewSubApply(t *testing.T) {
	var v View
	v.AppendOwned([]byte("0123"))
	v.AppendOwned([]byte("45678"))
	v.AppendOwned([]byte("9abcd"))

	data := []byte("0123456789abcd")

	for i := 0; i <= len(data); i++ {
		for j := i; j <= len(data); j++ {
			t.Run(fmt.Sprintf("SubApply(%d,%d)", i, j), func(t *testing.T) {
				var got []byte
				v.SubApply(i, j-i, func(b []byte) {
					got = append(got, b...)
				})
				if want := data[i:j]; !bytes.Equal(got, want) {
					t.Errorf("got = %q; want %q", got, want)
				}
			})
		}
	}
}

func doSaveAndLoad(t *testing.T, toSave, toLoad *View) {
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

func TestSaveRestoreViewEmpty(t *testing.T) {
	var toSave View
	var v View
	doSaveAndLoad(t, &toSave, &v)

	if got := v.pool.avail; got != nil {
		t.Errorf("pool is not in zero state: v.pool.avail = %v, want nil", got)
	}
	if got := v.Flatten(); len(got) != 0 {
		t.Errorf("v.Flatten() = %x, want []", got)
	}
}

func TestSaveRestoreView(t *testing.T) {
	// Create data that fits 2.5 slots.
	data := bytes.Join([][]byte{
		bytes.Repeat([]byte{1, 2}, defaultBufferSize),
		bytes.Repeat([]byte{3}, defaultBufferSize/2),
	}, nil)

	var toSave View
	toSave.Append(data)

	var v View
	doSaveAndLoad(t, &toSave, &v)

	// Next available slot at index 3; 0-2 slot are used.
	i := 3
	if got, want := &v.pool.avail[0], &v.pool.embeddedStorage[i]; got != want {
		t.Errorf("next available buffer points to %p, want %p (&v.pool.embeddedStorage[%d])", got, want, i)
	}
	if got := v.Flatten(); !bytes.Equal(got, data) {
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
