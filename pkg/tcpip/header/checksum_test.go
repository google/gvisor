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

// Package header provides the implementation of the encoding and decoding of
// network protocol headers.
package header_test

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestChecksumVVWithOffset(t *testing.T) {
	testCases := []struct {
		name      string
		vv        buffer.VectorisedView
		off, size int
		initial   uint16
		want      uint16
	}{
		{
			name: "empty",
			vv: buffer.NewVectorisedView(0, []buffer.View{
				buffer.NewViewFromBytes([]byte{1, 9, 0, 5, 4}),
			}),
			off:  0,
			size: 0,
			want: 0,
		},
		{
			name: "OneView",
			vv: buffer.NewVectorisedView(0, []buffer.View{
				buffer.NewViewFromBytes([]byte{1, 9, 0, 5, 4}),
			}),
			off:  0,
			size: 5,
			want: 1294,
		},
		{
			name: "TwoViews",
			vv: buffer.NewVectorisedView(0, []buffer.View{
				buffer.NewViewFromBytes([]byte{1, 9, 0, 5, 4}),
				buffer.NewViewFromBytes([]byte{4, 3, 7, 1, 2, 123}),
			}),
			off:  0,
			size: 11,
			want: 33819,
		},
		{
			name: "TwoViewsWithOffset",
			vv: buffer.NewVectorisedView(0, []buffer.View{
				buffer.NewViewFromBytes([]byte{98, 1, 9, 0, 5, 4}),
				buffer.NewViewFromBytes([]byte{4, 3, 7, 1, 2, 123}),
			}),
			off:  1,
			size: 11,
			want: 33819,
		},
		{
			name: "ThreeViewsWithOffset",
			vv: buffer.NewVectorisedView(0, []buffer.View{
				buffer.NewViewFromBytes([]byte{98, 1, 9, 0, 5, 4}),
				buffer.NewViewFromBytes([]byte{98, 1, 9, 0, 5, 4}),
				buffer.NewViewFromBytes([]byte{4, 3, 7, 1, 2, 123}),
			}),
			off:  7,
			size: 11,
			want: 33819,
		},
		{
			name: "ThreeViewsWithInitial",
			vv: buffer.NewVectorisedView(0, []buffer.View{
				buffer.NewViewFromBytes([]byte{77, 11, 33, 0, 55, 44}),
				buffer.NewViewFromBytes([]byte{98, 1, 9, 0, 5, 4}),
				buffer.NewViewFromBytes([]byte{4, 3, 7, 1, 2, 123, 99}),
			}),
			initial: 77,
			off:     7,
			size:    11,
			want:    33896,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := header.ChecksumVVWithOffset(tc.vv, tc.initial, tc.off, tc.size), tc.want; got != want {
				t.Errorf("header.ChecksumVVWithOffset(%v) = %v, want: %v", tc, got, tc.want)
			}
			v := tc.vv.ToView()
			v.TrimFront(tc.off)
			v.CapLength(tc.size)
			if got, want := header.Checksum(v, tc.initial), tc.want; got != want {
				t.Errorf("header.Checksum(%v) = %v, want: %v", tc, got, tc.want)
			}
		})
	}
}
