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

package cgroupfs

import (
	"fmt"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/bitmap"
)

// formatBitmap produces a string representation of b, which lists the indicies
// of set bits in the bitmap. Indicies are separated by commas and ranges of
// set bits are abbreviated. Example outputs: "0,2,4", "0,3-7,10", "0-10".
//
// Inverse of parseBitmap.
func formatBitmap(b *bitmap.Bitmap) string {
	ones := b.ToSlice()
	if len(ones) == 0 {
		return ""
	}

	elems := make([]string, 0, len(ones))
	runStart := ones[0]
	lastVal := ones[0]
	inRun := false

	for _, v := range ones[1:] {
		last := lastVal
		lastVal = v

		if last+1 == v {
			// In a contiguous block of ones.
			if !inRun {
				runStart = last
				inRun = true
			}

			continue
		}

		// Non-contiguous bit.
		if inRun {
			// Render a run
			elems = append(elems, fmt.Sprintf("%d-%d", runStart, last))
			inRun = false
			continue
		}

		// Lone non-contiguous bit.
		elems = append(elems, fmt.Sprintf("%d", last))

	}

	// Process potential final run
	if inRun {
		elems = append(elems, fmt.Sprintf("%d-%d", runStart, lastVal))
	} else {
		elems = append(elems, fmt.Sprintf("%d", lastVal))
	}

	return strings.Join(elems, ",")
}

func parseToken(token string) (start, end uint32, err error) {
	ts := strings.SplitN(token, "-", 2)
	switch len(ts) {
	case 0:
		return 0, 0, fmt.Errorf("invalid token %q", token)
	case 1:
		val, err := strconv.ParseUint(ts[0], 10, 32)
		if err != nil {
			return 0, 0, err
		}
		return uint32(val), uint32(val), nil
	case 2:
		val1, err := strconv.ParseUint(ts[0], 10, 32)
		if err != nil {
			return 0, 0, err
		}
		val2, err := strconv.ParseUint(ts[1], 10, 32)
		if err != nil {
			return 0, 0, err
		}
		if val1 >= val2 {
			return 0, 0, fmt.Errorf("start (%v) must be less than end (%v)", val1, val2)
		}
		return uint32(val1), uint32(val2), nil
	default:
		panic(fmt.Sprintf("Unreachable: got %d substrs", len(ts)))
	}
}

// parseBitmap parses input as a bitmap. input should be a comma separated list
// of indices, and ranges of set bits may be abbreviated. Examples: "0,2,4",
// "0,3-7,10", "0-10". Input after the first newline or null byte is discarded.
//
// sizeHint sets the initial size of the bitmap, which may prevent reallocation
// when growing the bitmap during parsing. Ideally sizeHint should be at least
// as large as the bitmap represented by input, but this is not required.
//
// Inverse of formatBitmap.
func parseBitmap(input string, sizeHint uint32) (*bitmap.Bitmap, error) {
	b := bitmap.New(sizeHint)

	if termIdx := strings.IndexAny(input, "\n\000"); termIdx != -1 {
		input = input[:termIdx]
	}
	input = strings.TrimSpace(input)

	if len(input) == 0 {
		return &b, nil
	}
	tokens := strings.Split(input, ",")

	for _, t := range tokens {
		start, end, err := parseToken(strings.TrimSpace(t))
		if err != nil {
			return nil, err
		}
		for i := start; i <= end; i++ {
			b.Add(i)
		}
	}
	return &b, nil
}
