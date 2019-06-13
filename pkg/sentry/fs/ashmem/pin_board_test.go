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

package ashmem

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

func TestPinBoard(t *testing.T) {
	pb := NewPinBoard()

	// Confirm that all pages are pinned.
	if !pb.RangePinnedStatus(RangeFromAshmemPin(linux.AshmemPin{0, 0})) {
		t.Errorf("RangePinnedStatus(all pages) returned false (unpinned) at start.")
	}

	// Unpin pages [1, 11) (counting from 0)
	pb.UnpinRange(RangeFromAshmemPin(linux.AshmemPin{
		usermem.PageSize,
		usermem.PageSize * 10,
	}))

	// Confirm that pages [1, 11) are unpinned and that page 0 and pages
	// larger than 10 are pinned.
	pinned := []linux.AshmemPin{
		{
			0,
			usermem.PageSize,
		}, {
			usermem.PageSize * 11,
			0,
		},
	}

	for _, pin := range pinned {
		if !pb.RangePinnedStatus(RangeFromAshmemPin(pin)) {
			t.Errorf("RangePinnedStatus(AshmemPin{offset (pages): %v, len (pages): %v}) returned false (unpinned).",
				pin.Offset, pin.Len)
		}
	}

	unpinned := []linux.AshmemPin{
		{
			usermem.PageSize,
			usermem.PageSize * 10,
		},
	}

	for _, pin := range unpinned {
		if pb.RangePinnedStatus(RangeFromAshmemPin(pin)) {
			t.Errorf("RangePinnedStatus(AshmemPin{offset (pages): %v, len (pages): %v}) returned true (pinned).",
				pin.Offset, pin.Len)
		}
	}

	// Pin pages [2, 6).
	pb.PinRange(RangeFromAshmemPin(linux.AshmemPin{
		usermem.PageSize * 2,
		usermem.PageSize * 4,
	}))

	// Confirm that pages 0, [2, 6) and pages larger than 10 are pinned
	// while others remain unpinned.
	pinned = []linux.AshmemPin{
		{
			0,
			usermem.PageSize,
		},
		{
			usermem.PageSize * 2,
			usermem.PageSize * 4,
		},
		{
			usermem.PageSize * 11,
			0,
		},
	}

	for _, pin := range pinned {
		if !pb.RangePinnedStatus(RangeFromAshmemPin(pin)) {
			t.Errorf("RangePinnedStatus(AshmemPin{offset (pages): %v, len (pages): %v}) returned false (unpinned).",
				pin.Offset, pin.Len)
		}
	}

	unpinned = []linux.AshmemPin{
		{
			usermem.PageSize,
			usermem.PageSize,
		}, {
			usermem.PageSize * 6,
			usermem.PageSize * 5,
		},
	}

	for _, pin := range unpinned {
		if pb.RangePinnedStatus(RangeFromAshmemPin(pin)) {
			t.Errorf("RangePinnedStatus(AshmemPin{offset (pages): %v, len (pages): %v}) returned true (pinned).",
				pin.Offset, pin.Len)
		}
	}

	// Status of a partially pinned range is unpinned.
	if pb.RangePinnedStatus(RangeFromAshmemPin(linux.AshmemPin{0, 0})) {
		t.Errorf("RangePinnedStatus(all pages) returned true (pinned).")
	}

	// Pin the whole range again.
	pb.PinRange(RangeFromAshmemPin(linux.AshmemPin{0, 0}))

	// Confirm that all pages are pinned.
	if !pb.RangePinnedStatus(RangeFromAshmemPin(linux.AshmemPin{0, 0})) {
		t.Errorf("RangePinnedStatus(all pages) returned false (unpinned) at start.")
	}
}
