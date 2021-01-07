// Copyright 2018 The gVisor Authors.
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

// Package buffer_test contains tests for the VectorisedView type.
package buffer

import (
	"bytes"
	"reflect"
	"testing"
)

// copy returns a deep-copy of the vectorised view.
func (vv VectorisedView) copy() VectorisedView {
	uu := VectorisedView{
		views: make([]View, 0, len(vv.views)),
		size:  vv.size,
	}
	for _, v := range vv.views {
		uu.views = append(uu.views, append(View(nil), v...))
	}
	return uu
}

// vv is an helper to build VectorisedView from different strings.
func vv(size int, pieces ...string) VectorisedView {
	views := make([]View, len(pieces))
	for i, p := range pieces {
		views[i] = []byte(p)
	}

	return NewVectorisedView(size, views)
}

var capLengthTestCases = []struct {
	comment string
	in      VectorisedView
	length  int
	want    VectorisedView
}{
	{
		comment: "Simple case",
		in:      vv(2, "12"),
		length:  1,
		want:    vv(1, "1"),
	},
	{
		comment: "Case spanning across two Views",
		in:      vv(4, "123", "4"),
		length:  2,
		want:    vv(2, "12"),
	},
	{
		comment: "Corner case with negative length",
		in:      vv(1, "1"),
		length:  -1,
		want:    vv(0),
	},
	{
		comment: "Corner case with length = 0",
		in:      vv(3, "12", "3"),
		length:  0,
		want:    vv(0),
	},
	{
		comment: "Corner case with length = size",
		in:      vv(1, "1"),
		length:  1,
		want:    vv(1, "1"),
	},
	{
		comment: "Corner case with length > size",
		in:      vv(1, "1"),
		length:  2,
		want:    vv(1, "1"),
	},
}

func TestCapLength(t *testing.T) {
	for _, c := range capLengthTestCases {
		orig := c.in.copy()
		c.in.CapLength(c.length)
		if !reflect.DeepEqual(c.in, c.want) {
			t.Errorf("Test \"%s\" failed when calling CapLength(%d) on %v. Got %v. Want %v",
				c.comment, c.length, orig, c.in, c.want)
		}
	}
}

var trimFrontTestCases = []struct {
	comment string
	in      VectorisedView
	count   int
	want    VectorisedView
}{
	{
		comment: "Simple case",
		in:      vv(2, "12"),
		count:   1,
		want:    vv(1, "2"),
	},
	{
		comment: "Case where we trim an entire View",
		in:      vv(2, "1", "2"),
		count:   1,
		want:    vv(1, "2"),
	},
	{
		comment: "Case spanning across two Views",
		in:      vv(3, "1", "23"),
		count:   2,
		want:    vv(1, "3"),
	},
	{
		comment: "Corner case with negative count",
		in:      vv(1, "1"),
		count:   -1,
		want:    vv(1, "1"),
	},
	{
		comment: " Corner case with count = 0",
		in:      vv(1, "1"),
		count:   0,
		want:    vv(1, "1"),
	},
	{
		comment: "Corner case with count = size",
		in:      vv(1, "1"),
		count:   1,
		want:    vv(0),
	},
	{
		comment: "Corner case with count > size",
		in:      vv(1, "1"),
		count:   2,
		want:    vv(0),
	},
}

func TestTrimFront(t *testing.T) {
	for _, c := range trimFrontTestCases {
		orig := c.in.copy()
		c.in.TrimFront(c.count)
		if !reflect.DeepEqual(c.in, c.want) {
			t.Errorf("Test \"%s\" failed when calling TrimFront(%d) on %v. Got %v. Want %v",
				c.comment, c.count, orig, c.in, c.want)
		}
	}
}

var toViewCases = []struct {
	comment string
	in      VectorisedView
	want    View
}{
	{
		comment: "Simple case",
		in:      vv(2, "12"),
		want:    []byte("12"),
	},
	{
		comment: "Case with multiple views",
		in:      vv(2, "1", "2"),
		want:    []byte("12"),
	},
	{
		comment: "Empty case",
		in:      vv(0),
		want:    []byte(""),
	},
}

func TestToView(t *testing.T) {
	for _, c := range toViewCases {
		got := c.in.ToView()
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Test \"%s\" failed when calling ToView() on %v. Got %v. Want %v",
				c.comment, c.in, got, c.want)
		}
	}
}

var toCloneCases = []struct {
	comment  string
	inView   VectorisedView
	inBuffer []View
}{
	{
		comment:  "Simple case",
		inView:   vv(1, "1"),
		inBuffer: make([]View, 1),
	},
	{
		comment:  "Case with multiple views",
		inView:   vv(2, "1", "2"),
		inBuffer: make([]View, 2),
	},
	{
		comment:  "Case with buffer too small",
		inView:   vv(2, "1", "2"),
		inBuffer: make([]View, 1),
	},
	{
		comment:  "Case with buffer larger than needed",
		inView:   vv(1, "1"),
		inBuffer: make([]View, 2),
	},
	{
		comment:  "Case with nil buffer",
		inView:   vv(1, "1"),
		inBuffer: nil,
	},
}

func TestToClone(t *testing.T) {
	for _, c := range toCloneCases {
		t.Run(c.comment, func(t *testing.T) {
			got := c.inView.Clone(c.inBuffer)
			if !reflect.DeepEqual(got, c.inView) {
				t.Fatalf("got (%+v).Clone(%+v) = %+v, want = %+v",
					c.inView, c.inBuffer, got, c.inView)
			}
		})
	}
}

type readToTestCases struct {
	comment     string
	vv          VectorisedView
	bytesToRead int
	wantBytes   string
	leftVV      VectorisedView
}

func createReadToTestCases() []readToTestCases {
	return []readToTestCases{
		{
			comment:     "large VV, short read",
			vv:          vv(30, "012345678901234567890123456789"),
			bytesToRead: 10,
			wantBytes:   "0123456789",
			leftVV:      vv(20, "01234567890123456789"),
		},
		{
			comment:     "largeVV, multiple views, short read",
			vv:          vv(13, "123", "345", "567", "8910"),
			bytesToRead: 6,
			wantBytes:   "123345",
			leftVV:      vv(7, "567", "8910"),
		},
		{
			comment:     "smallVV (multiple views), large read",
			vv:          vv(3, "1", "2", "3"),
			bytesToRead: 10,
			wantBytes:   "123",
			leftVV:      vv(0, ""),
		},
		{
			comment:     "smallVV (single view), large read",
			vv:          vv(1, "1"),
			bytesToRead: 10,
			wantBytes:   "1",
			leftVV:      vv(0, ""),
		},
		{
			comment:     "emptyVV, large read",
			vv:          vv(0, ""),
			bytesToRead: 10,
			wantBytes:   "",
			leftVV:      vv(0, ""),
		},
	}
}

func TestVVReadToVV(t *testing.T) {
	for _, tc := range createReadToTestCases() {
		t.Run(tc.comment, func(t *testing.T) {
			var readTo VectorisedView
			inSize := tc.vv.Size()
			copied := tc.vv.ReadToVV(&readTo, tc.bytesToRead)
			if got, want := copied, len(tc.wantBytes); got != want {
				t.Errorf("incorrect number of bytes copied returned in ReadToVV got: %d, want: %d, tc: %+v", got, want, tc)
			}
			if got, want := string(readTo.ToView()), tc.wantBytes; got != want {
				t.Errorf("unexpected content in readTo got: %s, want: %s", got, want)
			}
			if got, want := tc.vv.Size(), inSize-copied; got != want {
				t.Errorf("test VV has incorrect size after reading got: %d, want: %d, tc.vv: %+v", got, want, tc.vv)
			}
			if got, want := string(tc.vv.ToView()), string(tc.leftVV.ToView()); got != want {
				t.Errorf("unexpected data left in vv after read got: %+v, want: %+v", got, want)
			}
		})
	}
}

func TestVVReadTo(t *testing.T) {
	for _, tc := range createReadToTestCases() {
		t.Run(tc.comment, func(t *testing.T) {
			var dst bytes.Buffer
			origSize := tc.vv.Size()
			copied, err := tc.vv.ReadTo(&dst, tc.bytesToRead, false /* peek */)
			if got, want := copied, len(tc.wantBytes); err != nil || got != want {
				t.Errorf("got ReadTo(&dst, %d, false) = %d, %v; want %d, nil", tc.bytesToRead, got, err, want)
			}
			if got, want := string(dst.Bytes()), tc.wantBytes; got != want {
				t.Errorf("got dst = %q, want %q", got, want)
			}
			if got, want := tc.vv.Size(), origSize-copied; got != want {
				t.Errorf("got after-read tc.vv.Size() = %d, want %d", got, want)
			}
			if got, want := string(tc.vv.ToView()), string(tc.leftVV.ToView()); got != want {
				t.Errorf("got after-read data in tc.vv = %q, want %q", got, want)
			}
		})
	}
}

func TestVVReadToPeek(t *testing.T) {
	for _, tc := range createReadToTestCases() {
		t.Run(tc.comment, func(t *testing.T) {
			var dst bytes.Buffer
			origSize := tc.vv.Size()
			origData := string(tc.vv.ToView())
			copied, err := tc.vv.ReadTo(&dst, tc.bytesToRead, true /* peek */)
			if got, want := copied, len(tc.wantBytes); err != nil || got != want {
				t.Errorf("got ReadTo(&dst, %d, false) = %d, %v; want %d, nil", tc.bytesToRead, got, err, want)
			}
			if got, want := string(dst.Bytes()), tc.wantBytes; got != want {
				t.Errorf("got dst = %q, want %q", got, want)
			}
			// Expect tc.vv is unchanged.
			if got, want := tc.vv.Size(), origSize; got != want {
				t.Errorf("got after-read tc.vv.Size() = %d, want %d", got, want)
			}
			if got, want := string(tc.vv.ToView()), origData; got != want {
				t.Errorf("got after-read data in tc.vv = %q, want %q", got, want)
			}
		})
	}
}

func TestVVRead(t *testing.T) {
	testCases := []struct {
		comment     string
		vv          VectorisedView
		bytesToRead int
		readBytes   string
		leftBytes   string
		wantError   bool
	}{
		{
			comment:     "large VV, short read",
			vv:          vv(30, "012345678901234567890123456789"),
			bytesToRead: 10,
			readBytes:   "0123456789",
			leftBytes:   "01234567890123456789",
		},
		{
			comment:     "largeVV, multiple buffers, short read",
			vv:          vv(13, "123", "345", "567", "8910"),
			bytesToRead: 6,
			readBytes:   "123345",
			leftBytes:   "5678910",
		},
		{
			comment:     "smallVV, large read",
			vv:          vv(3, "1", "2", "3"),
			bytesToRead: 10,
			readBytes:   "123",
			leftBytes:   "",
		},
		{
			comment:     "smallVV, large read",
			vv:          vv(1, "1"),
			bytesToRead: 10,
			readBytes:   "1",
			leftBytes:   "",
		},
		{
			comment:     "emptyVV, large read",
			vv:          vv(0, ""),
			bytesToRead: 10,
			readBytes:   "",
			wantError:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.comment, func(t *testing.T) {
			readTo := NewView(tc.bytesToRead)
			inSize := tc.vv.Size()
			copied, err := tc.vv.Read(readTo)
			if !tc.wantError && err != nil {
				t.Fatalf("unexpected error in tc.vv.Read(..) = %s", err)
			}
			readTo = readTo[:copied]
			if got, want := copied, len(tc.readBytes); got != want {
				t.Errorf("incorrect number of bytes copied returned in ReadToVV got: %d, want: %d, tc.vv: %+v", got, want, tc.vv)
			}
			if got, want := string(readTo), tc.readBytes; got != want {
				t.Errorf("unexpected data in readTo got: %s, want: %s", got, want)
			}
			if got, want := tc.vv.Size(), inSize-copied; got != want {
				t.Errorf("test VV has incorrect size after reading got: %d, want: %d, tc.vv: %+v", got, want, tc.vv)
			}
			if got, want := string(tc.vv.ToView()), tc.leftBytes; got != want {
				t.Errorf("vv has incorrect data after Read got: %s, want: %s", got, want)
			}
		})
	}
}

var pullUpTestCases = []struct {
	comment string
	in      VectorisedView
	count   int
	want    []byte
	result  VectorisedView
	ok      bool
}{
	{
		comment: "simple case",
		in:      vv(2, "12"),
		count:   1,
		want:    []byte("1"),
		result:  vv(2, "12"),
		ok:      true,
	},
	{
		comment: "entire View",
		in:      vv(2, "1", "2"),
		count:   1,
		want:    []byte("1"),
		result:  vv(2, "1", "2"),
		ok:      true,
	},
	{
		comment: "spanning across two Views",
		in:      vv(3, "1", "23"),
		count:   2,
		want:    []byte("12"),
		result:  vv(3, "12", "3"),
		ok:      true,
	},
	{
		comment: "spanning across all Views",
		in:      vv(5, "1", "23", "45"),
		count:   5,
		want:    []byte("12345"),
		result:  vv(5, "12345"),
		ok:      true,
	},
	{
		comment: "count = 0",
		in:      vv(1, "1"),
		count:   0,
		want:    []byte{},
		result:  vv(1, "1"),
		ok:      true,
	},
	{
		comment: "count = size",
		in:      vv(1, "1"),
		count:   1,
		want:    []byte("1"),
		result:  vv(1, "1"),
		ok:      true,
	},
	{
		comment: "count too large",
		in:      vv(3, "1", "23"),
		count:   4,
		want:    nil,
		result:  vv(3, "1", "23"),
		ok:      false,
	},
	{
		comment: "empty vv",
		in:      vv(0, ""),
		count:   1,
		want:    nil,
		result:  vv(0, ""),
		ok:      false,
	},
	{
		comment: "empty vv, count = 0",
		in:      vv(0, ""),
		count:   0,
		want:    nil,
		result:  vv(0, ""),
		ok:      true,
	},
	{
		comment: "empty views",
		in:      vv(3, "", "1", "", "23"),
		count:   2,
		want:    []byte("12"),
		result:  vv(3, "12", "3"),
		ok:      true,
	},
}

func TestPullUp(t *testing.T) {
	for _, c := range pullUpTestCases {
		got, ok := c.in.PullUp(c.count)

		// Is the return value right?
		if ok != c.ok {
			t.Errorf("Test %q failed when calling PullUp(%d) on %v. Got an ok of %t. Want %t",
				c.comment, c.count, c.in, ok, c.ok)
		}
		if bytes.Compare(got, View(c.want)) != 0 {
			t.Errorf("Test %q failed when calling PullUp(%d) on %v. Got %v. Want %v",
				c.comment, c.count, c.in, got, c.want)
		}

		// Is the underlying structure right?
		if !reflect.DeepEqual(c.in, c.result) {
			t.Errorf("Test %q failed when calling PullUp(%d). Got vv with structure %v. Wanted %v",
				c.comment, c.count, c.in, c.result)
		}
	}
}

func TestToVectorisedView(t *testing.T) {
	testCases := []struct {
		in   View
		want VectorisedView
	}{
		{nil, VectorisedView{}},
		{View{}, VectorisedView{}},
		{View{'a'}, VectorisedView{size: 1, views: []View{{'a'}}}},
	}
	for _, tc := range testCases {
		if got, want := tc.in.ToVectorisedView(), tc.want; !reflect.DeepEqual(got, want) {
			t.Errorf("(%v).ToVectorisedView failed got: %+v, want: %+v", tc.in, got, want)
		}
	}
}

func TestAppendView(t *testing.T) {
	testCases := []struct {
		vv   VectorisedView
		in   View
		want VectorisedView
	}{
		{VectorisedView{}, nil, VectorisedView{}},
		{VectorisedView{}, View{}, VectorisedView{}},
		{VectorisedView{[]View{{'a', 'b', 'c', 'd'}}, 4}, nil, VectorisedView{[]View{{'a', 'b', 'c', 'd'}}, 4}},
		{VectorisedView{[]View{{'a', 'b', 'c', 'd'}}, 4}, View{}, VectorisedView{[]View{{'a', 'b', 'c', 'd'}}, 4}},
		{VectorisedView{[]View{{'a', 'b', 'c', 'd'}}, 4}, View{'e'}, VectorisedView{[]View{{'a', 'b', 'c', 'd'}, {'e'}}, 5}},
	}
	for _, tc := range testCases {
		tc.vv.AppendView(tc.in)
		if got, want := tc.vv, tc.want; !reflect.DeepEqual(got, want) {
			t.Errorf("(%v).ToVectorisedView failed got: %+v, want: %+v", tc.in, got, want)
		}
	}
}
