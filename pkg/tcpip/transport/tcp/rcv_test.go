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

package tcp_test

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

func TestAcceptable(t *testing.T) {
	for _, tt := range []struct {
		segSeq         seqnum.Value
		segLen         seqnum.Size
		rcvNxt, rcvAcc seqnum.Value
		want           bool
	}{
		// The segment is smaller than the window.
		{105, 2, 100, 104, false},
		{105, 2, 101, 105, true},
		{105, 2, 102, 106, true},
		{105, 2, 103, 107, true},
		{105, 2, 104, 108, true},
		{105, 2, 105, 109, true},
		{105, 2, 106, 110, true},
		{105, 2, 107, 111, false},

		// The segment is larger than the window.
		{105, 4, 103, 105, true},
		{105, 4, 104, 106, true},
		{105, 4, 105, 107, true},
		{105, 4, 106, 108, true},
		{105, 4, 107, 109, true},
		{105, 4, 108, 110, true},
		{105, 4, 109, 111, false},
		{105, 4, 110, 112, false},

		// The segment has no width.
		{105, 0, 100, 102, false},
		{105, 0, 101, 103, false},
		{105, 0, 102, 104, false},
		{105, 0, 103, 105, true},
		{105, 0, 104, 106, true},
		{105, 0, 105, 107, true},
		{105, 0, 106, 108, false},
		{105, 0, 107, 109, false},

		// The receive window has no width.
		{105, 2, 103, 103, false},
		{105, 2, 104, 104, false},
		{105, 2, 105, 105, false},
		{105, 2, 106, 106, false},
		{105, 2, 107, 107, false},
		{105, 2, 108, 108, false},
		{105, 2, 109, 109, false},
	} {
		if got := header.Acceptable(tt.segSeq, tt.segLen, tt.rcvNxt, tt.rcvAcc); got != tt.want {
			t.Errorf("header.Acceptable(%d, %d, %d, %d) = %t, want %t", tt.segSeq, tt.segLen, tt.rcvNxt, tt.rcvAcc, got, tt.want)
		}
	}
}
