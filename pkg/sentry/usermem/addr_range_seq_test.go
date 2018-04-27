// Copyright 2018 Google Inc.
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

package usermem

import (
	"testing"
)

var addrRangeSeqTests = []struct {
	desc   string
	ranges []AddrRange
}{
	{
		desc: "Empty sequence",
	},
	{
		desc: "Single empty AddrRange",
		ranges: []AddrRange{
			{0x10, 0x10},
		},
	},
	{
		desc: "Single non-empty AddrRange of length 1",
		ranges: []AddrRange{
			{0x10, 0x11},
		},
	},
	{
		desc: "Single non-empty AddrRange of length 2",
		ranges: []AddrRange{
			{0x10, 0x12},
		},
	},
	{
		desc: "Multiple non-empty AddrRanges",
		ranges: []AddrRange{
			{0x10, 0x11},
			{0x20, 0x22},
		},
	},
	{
		desc: "Multiple AddrRanges including empty AddrRanges",
		ranges: []AddrRange{
			{0x10, 0x10},
			{0x20, 0x20},
			{0x30, 0x33},
			{0x40, 0x44},
			{0x50, 0x50},
			{0x60, 0x60},
			{0x70, 0x77},
			{0x80, 0x88},
			{0x90, 0x90},
			{0xa0, 0xa0},
		},
	},
}

func testAddrRangeSeqEqualityWithTailIteration(t *testing.T, ars AddrRangeSeq, wantRanges []AddrRange) {
	var wantLen int64
	for _, ar := range wantRanges {
		wantLen += int64(ar.Length())
	}

	var i int
	for !ars.IsEmpty() {
		if gotLen := ars.NumBytes(); gotLen != wantLen {
			t.Errorf("Iteration %d: %v.NumBytes(): got %d, wanted %d", i, ars, gotLen, wantLen)
		}
		if gotN, wantN := ars.NumRanges(), len(wantRanges)-i; gotN != wantN {
			t.Errorf("Iteration %d: %v.NumRanges(): got %d, wanted %d", i, ars, gotN, wantN)
		}
		got := ars.Head()
		if i >= len(wantRanges) {
			t.Errorf("Iteration %d: %v.Head(): got %s, wanted <end of sequence>", i, ars, got)
		} else if want := wantRanges[i]; got != want {
			t.Errorf("Iteration %d: %v.Head(): got %s, wanted %s", i, ars, got, want)
		}
		ars = ars.Tail()
		wantLen -= int64(got.Length())
		i++
	}
	if gotLen := ars.NumBytes(); gotLen != 0 || wantLen != 0 {
		t.Errorf("Iteration %d: %v.NumBytes(): got %d, wanted %d (which should be 0)", i, ars, gotLen, wantLen)
	}
	if gotN := ars.NumRanges(); gotN != 0 {
		t.Errorf("Iteration %d: %v.NumRanges(): got %d, wanted 0", i, ars, gotN)
	}
}

func TestAddrRangeSeqTailIteration(t *testing.T) {
	for _, test := range addrRangeSeqTests {
		t.Run(test.desc, func(t *testing.T) {
			testAddrRangeSeqEqualityWithTailIteration(t, AddrRangeSeqFromSlice(test.ranges), test.ranges)
		})
	}
}

func TestAddrRangeSeqDropFirstEmpty(t *testing.T) {
	var ars AddrRangeSeq
	if got, want := ars.DropFirst(1), ars; got != want {
		t.Errorf("%v.DropFirst(1): got %v, wanted %v", ars, got, want)
	}
}

func TestAddrRangeSeqDropSingleByteIteration(t *testing.T) {
	// Tests AddrRangeSeq iteration using Head/DropFirst, simulating
	// I/O-per-AddrRange.
	for _, test := range addrRangeSeqTests {
		t.Run(test.desc, func(t *testing.T) {
			// Figure out what AddrRanges we expect to see.
			var wantLen int64
			var wantRanges []AddrRange
			for _, ar := range test.ranges {
				wantLen += int64(ar.Length())
				wantRanges = append(wantRanges, ar)
				if ar.Length() == 0 {
					// We "do" 0 bytes of I/O and then call DropFirst(0),
					// advancing to the next AddrRange.
					continue
				}
				// Otherwise we "do" 1 byte of I/O and then call DropFirst(1),
				// advancing the AddrRange by 1 byte, or to the next AddrRange
				// if this one is exhausted.
				for ar.Start++; ar.Length() != 0; ar.Start++ {
					wantRanges = append(wantRanges, ar)
				}
			}
			t.Logf("Expected AddrRanges: %s (%d bytes)", wantRanges, wantLen)

			ars := AddrRangeSeqFromSlice(test.ranges)
			var i int
			for !ars.IsEmpty() {
				if gotLen := ars.NumBytes(); gotLen != wantLen {
					t.Errorf("Iteration %d: %v.NumBytes(): got %d, wanted %d", i, ars, gotLen, wantLen)
				}
				got := ars.Head()
				if i >= len(wantRanges) {
					t.Errorf("Iteration %d: %v.Head(): got %s, wanted <end of sequence>", i, ars, got)
				} else if want := wantRanges[i]; got != want {
					t.Errorf("Iteration %d: %v.Head(): got %s, wanted %s", i, ars, got, want)
				}
				if got.Length() == 0 {
					ars = ars.DropFirst(0)
				} else {
					ars = ars.DropFirst(1)
					wantLen--
				}
				i++
			}
			if gotLen := ars.NumBytes(); gotLen != 0 || wantLen != 0 {
				t.Errorf("Iteration %d: %v.NumBytes(): got %d, wanted %d (which should be 0)", i, ars, gotLen, wantLen)
			}
		})
	}
}

func TestAddrRangeSeqTakeFirstEmpty(t *testing.T) {
	var ars AddrRangeSeq
	if got, want := ars.TakeFirst(1), ars; got != want {
		t.Errorf("%v.TakeFirst(1): got %v, wanted %v", ars, got, want)
	}
}

func TestAddrRangeSeqTakeFirst(t *testing.T) {
	ranges := []AddrRange{
		{0x10, 0x11},
		{0x20, 0x22},
		{0x30, 0x30},
		{0x40, 0x44},
		{0x50, 0x55},
		{0x60, 0x60},
		{0x70, 0x77},
	}
	ars := AddrRangeSeqFromSlice(ranges).TakeFirst(5)
	want := []AddrRange{
		{0x10, 0x11}, // +1 byte (total 1 byte), not truncated
		{0x20, 0x22}, // +2 bytes (total 3 bytes), not truncated
		{0x30, 0x30}, // +0 bytes (total 3 bytes), no change
		{0x40, 0x42}, // +2 bytes (total 5 bytes), partially truncated
		{0x50, 0x50}, // +0 bytes (total 5 bytes), fully truncated
		{0x60, 0x60}, // +0 bytes (total 5 bytes), "fully truncated" (no change)
		{0x70, 0x70}, // +0 bytes (total 5 bytes), fully truncated
	}
	testAddrRangeSeqEqualityWithTailIteration(t, ars, want)
}
