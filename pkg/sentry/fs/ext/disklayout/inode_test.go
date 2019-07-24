// Copyright 2019 The gVisor Authors.
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

package disklayout

import (
	"fmt"
	"strconv"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

// TestInodeSize tests that the inode structs are of the correct size.
func TestInodeSize(t *testing.T) {
	assertSize(t, InodeOld{}, OldInodeSize)

	// This was updated from 156 bytes to 160 bytes in Oct 2015.
	assertSize(t, InodeNew{}, 160)
}

// TestTimestampSeconds tests that the seconds part of [a/c/m] timestamps in
// ext4 inode structs are decoded correctly.
//
// These tests are derived from the table under https://www.kernel.org/doc/html/latest/filesystems/ext4/dynamic.html#inode-timestamps.
func TestTimestampSeconds(t *testing.T) {
	type timestampTest struct {
		// msbSet tells if the most significant bit of InodeOld.[X]TimeRaw is set.
		// If this is set then the 32-bit time is negative.
		msbSet bool

		// lowerBound tells if we should take the lowest possible value of
		// InodeOld.[X]TimeRaw while satisfying test.msbSet condition. If set to
		// false it tells to take the highest possible value.
		lowerBound bool

		// extraBits is InodeNew.[X]TimeExtra.
		extraBits uint32

		// want is the kernel time struct that is expected.
		want time.Time
	}

	tests := []timestampTest{
		// 1901-12-13
		{
			msbSet:     true,
			lowerBound: true,
			extraBits:  0,
			want:       time.FromUnix(int64(-0x80000000), 0),
		},

		// 1969-12-31
		{
			msbSet:     true,
			lowerBound: false,
			extraBits:  0,
			want:       time.FromUnix(int64(-1), 0),
		},

		// 1970-01-01
		{
			msbSet:     false,
			lowerBound: true,
			extraBits:  0,
			want:       time.FromUnix(int64(0), 0),
		},

		// 2038-01-19
		{
			msbSet:     false,
			lowerBound: false,
			extraBits:  0,
			want:       time.FromUnix(int64(0x7fffffff), 0),
		},

		// 2038-01-19
		{
			msbSet:     true,
			lowerBound: true,
			extraBits:  1,
			want:       time.FromUnix(int64(0x80000000), 0),
		},

		// 2106-02-07
		{
			msbSet:     true,
			lowerBound: false,
			extraBits:  1,
			want:       time.FromUnix(int64(0xffffffff), 0),
		},

		// 2106-02-07
		{
			msbSet:     false,
			lowerBound: true,
			extraBits:  1,
			want:       time.FromUnix(int64(0x100000000), 0),
		},

		// 2174-02-25
		{
			msbSet:     false,
			lowerBound: false,
			extraBits:  1,
			want:       time.FromUnix(int64(0x17fffffff), 0),
		},

		// 2174-02-25
		{
			msbSet:     true,
			lowerBound: true,
			extraBits:  2,
			want:       time.FromUnix(int64(0x180000000), 0),
		},

		// 2242-03-16
		{
			msbSet:     true,
			lowerBound: false,
			extraBits:  2,
			want:       time.FromUnix(int64(0x1ffffffff), 0),
		},

		// 2242-03-16
		{
			msbSet:     false,
			lowerBound: true,
			extraBits:  2,
			want:       time.FromUnix(int64(0x200000000), 0),
		},

		// 2310-04-04
		{
			msbSet:     false,
			lowerBound: false,
			extraBits:  2,
			want:       time.FromUnix(int64(0x27fffffff), 0),
		},

		// 2310-04-04
		{
			msbSet:     true,
			lowerBound: true,
			extraBits:  3,
			want:       time.FromUnix(int64(0x280000000), 0),
		},

		// 2378-04-22
		{
			msbSet:     true,
			lowerBound: false,
			extraBits:  3,
			want:       time.FromUnix(int64(0x2ffffffff), 0),
		},

		// 2378-04-22
		{
			msbSet:     false,
			lowerBound: true,
			extraBits:  3,
			want:       time.FromUnix(int64(0x300000000), 0),
		},

		// 2446-05-10
		{
			msbSet:     false,
			lowerBound: false,
			extraBits:  3,
			want:       time.FromUnix(int64(0x37fffffff), 0),
		},
	}

	lowerMSB0 := int32(0)           // binary: 00000000 00000000 00000000 00000000
	upperMSB0 := int32(0x7fffffff)  // binary: 01111111 11111111 11111111 11111111
	lowerMSB1 := int32(-0x80000000) // binary: 10000000 00000000 00000000 00000000
	upperMSB1 := int32(-1)          // binary: 11111111 11111111 11111111 11111111

	get32BitTime := func(test timestampTest) int32 {
		if test.msbSet {
			if test.lowerBound {
				return lowerMSB1
			}

			return upperMSB1
		}

		if test.lowerBound {
			return lowerMSB0
		}

		return upperMSB0
	}

	getTestName := func(test timestampTest) string {
		return fmt.Sprintf(
			"Tests time decoding with epoch bits 0b%s and 32-bit raw time: MSB set=%t, lower bound=%t",
			strconv.FormatInt(int64(test.extraBits), 2),
			test.msbSet,
			test.lowerBound,
		)
	}

	for _, test := range tests {
		t.Run(getTestName(test), func(t *testing.T) {
			if got := fromExtraTime(get32BitTime(test), test.extraBits); got != test.want {
				t.Errorf("Expected: %v, Got: %v", test.want, got)
			}
		})
	}
}
