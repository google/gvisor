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

package safemem

import (
	"bytes"
	"reflect"
	"testing"
)

func TestBlockSeqOfEmptyBlock(t *testing.T) {
	bs := BlockSeqOf(Block{})
	if !bs.IsEmpty() {
		t.Errorf("BlockSeqOf(Block{}).IsEmpty(): got false, wanted true; BlockSeq is %v", bs)
	}
}

func TestBlockSeqOfNonemptyBlock(t *testing.T) {
	b := BlockFromSafeSlice(make([]byte, 1))
	bs := BlockSeqOf(b)
	if bs.IsEmpty() {
		t.Fatalf("BlockSeqOf(non-empty Block).IsEmpty(): got true, wanted false; BlockSeq is %v", bs)
	}
	if head := bs.Head(); head != b {
		t.Fatalf("BlockSeqOf(non-empty Block).Head(): got %v, wanted %v", head, b)
	}
	if tail := bs.Tail(); !tail.IsEmpty() {
		t.Fatalf("BlockSeqOf(non-empty Block).Tail().IsEmpty(): got false, wanted true: tail is %v", tail)
	}
}

type blockSeqTest struct {
	desc string

	pieces     []string
	haveOffset bool
	offset     uint64
	haveLimit  bool
	limit      uint64

	want string
}

func (t blockSeqTest) NonEmptyByteSlices() [][]byte {
	// t is a value, so we can mutate it freely.
	slices := make([][]byte, 0, len(t.pieces))
	for _, str := range t.pieces {
		if t.haveOffset {
			strOff := t.offset
			if strOff > uint64(len(str)) {
				strOff = uint64(len(str))
			}
			str = str[strOff:]
			t.offset -= strOff
		}
		if t.haveLimit {
			strLim := t.limit
			if strLim > uint64(len(str)) {
				strLim = uint64(len(str))
			}
			str = str[:strLim]
			t.limit -= strLim
		}
		if len(str) != 0 {
			slices = append(slices, []byte(str))
		}
	}
	return slices
}

func (t blockSeqTest) BlockSeq() BlockSeq {
	blocks := make([]Block, 0, len(t.pieces))
	for _, str := range t.pieces {
		blocks = append(blocks, BlockFromSafeSlice([]byte(str)))
	}
	bs := BlockSeqFromSlice(blocks)
	if t.haveOffset {
		bs = bs.DropFirst64(t.offset)
	}
	if t.haveLimit {
		bs = bs.TakeFirst64(t.limit)
	}
	return bs
}

var blockSeqTests = []blockSeqTest{
	{
		desc: "Empty sequence",
	},
	{
		desc:   "Sequence of length 1",
		pieces: []string{"foobar"},
		want:   "foobar",
	},
	{
		desc:   "Sequence of length 2",
		pieces: []string{"foo", "bar"},
		want:   "foobar",
	},
	{
		desc:   "Empty Blocks",
		pieces: []string{"", "foo", "", "", "bar", ""},
		want:   "foobar",
	},
	{
		desc:       "Sequence with non-zero offset",
		pieces:     []string{"foo", "bar"},
		haveOffset: true,
		offset:     2,
		want:       "obar",
	},
	{
		desc:      "Sequence with non-maximal limit",
		pieces:    []string{"foo", "bar"},
		haveLimit: true,
		limit:     5,
		want:      "fooba",
	},
	{
		desc:       "Sequence with offset and limit",
		pieces:     []string{"foo", "bar"},
		haveOffset: true,
		offset:     2,
		haveLimit:  true,
		limit:      3,
		want:       "oba",
	},
}

func TestBlockSeqNumBytes(t *testing.T) {
	for _, test := range blockSeqTests {
		t.Run(test.desc, func(t *testing.T) {
			if got, want := test.BlockSeq().NumBytes(), uint64(len(test.want)); got != want {
				t.Errorf("NumBytes: got %d, wanted %d", got, want)
			}
		})
	}
}

func TestBlockSeqIterBlocks(t *testing.T) {
	// Tests BlockSeq iteration using Head/Tail.
	for _, test := range blockSeqTests {
		t.Run(test.desc, func(t *testing.T) {
			srcs := test.BlockSeq()
			// "Note that a non-nil empty slice and a nil slice ... are not
			// deeply equal." - reflect
			slices := make([][]byte, 0, 0)
			for !srcs.IsEmpty() {
				src := srcs.Head()
				slices = append(slices, src.ToSlice())
				nextSrcs := srcs.Tail()
				if got, want := nextSrcs.NumBytes(), srcs.NumBytes()-uint64(src.Len()); got != want {
					t.Fatalf("%v.Tail(): got %v (%d bytes), wanted %d bytes", srcs, nextSrcs, got, want)
				}
				srcs = nextSrcs
			}
			if wantSlices := test.NonEmptyByteSlices(); !reflect.DeepEqual(slices, wantSlices) {
				t.Errorf("Accumulated slices: got %v, wanted %v", slices, wantSlices)
			}
		})
	}
}

func TestBlockSeqIterBytes(t *testing.T) {
	// Tests BlockSeq iteration using Head/DropFirst.
	for _, test := range blockSeqTests {
		t.Run(test.desc, func(t *testing.T) {
			srcs := test.BlockSeq()
			var dst bytes.Buffer
			for !srcs.IsEmpty() {
				src := srcs.Head()
				var b [1]byte
				n, err := Copy(BlockFromSafeSlice(b[:]), src)
				if n != 1 || err != nil {
					t.Fatalf("Copy: got (%v, %v), wanted (1, nil)", n, err)
				}
				dst.WriteByte(b[0])
				nextSrcs := srcs.DropFirst(1)
				if got, want := nextSrcs.NumBytes(), srcs.NumBytes()-1; got != want {
					t.Fatalf("%v.DropFirst(1): got %v (%d bytes), wanted %d bytes", srcs, nextSrcs, got, want)
				}
				srcs = nextSrcs
			}
			if got := string(dst.Bytes()); got != test.want {
				t.Errorf("Copied string: got %q, wanted %q", got, test.want)
			}
		})
	}
}

func TestBlockSeqDropBeyondLimit(t *testing.T) {
	blocks := []Block{BlockFromSafeSlice([]byte("123")), BlockFromSafeSlice([]byte("4"))}
	bs := BlockSeqFromSlice(blocks)
	if got, want := bs.NumBytes(), uint64(4); got != want {
		t.Errorf("%v.NumBytes(): got %d, wanted %d", bs, got, want)
	}
	bs = bs.TakeFirst(1)
	if got, want := bs.NumBytes(), uint64(1); got != want {
		t.Errorf("%v.NumBytes(): got %d, wanted %d", bs, got, want)
	}
	bs = bs.DropFirst(2)
	if got, want := bs.NumBytes(), uint64(0); got != want {
		t.Errorf("%v.NumBytes(): got %d, wanted %d", bs, got, want)
	}
}
