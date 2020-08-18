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
	"io"
	"strings"
	"testing"
)

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
