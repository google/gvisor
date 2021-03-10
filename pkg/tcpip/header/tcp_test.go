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

package header_test

import (
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestEncodeSACKBlocks(t *testing.T) {
	testCases := []struct {
		sackBlocks []header.SACKBlock
		want       []header.SACKBlock
		bufSize    int
	}{
		{
			[]header.SACKBlock{{10, 20}, {22, 30}, {32, 40}, {42, 50}, {52, 60}, {62, 70}},
			[]header.SACKBlock{{10, 20}, {22, 30}, {32, 40}, {42, 50}},
			40,
		},
		{
			[]header.SACKBlock{{10, 20}, {22, 30}, {32, 40}, {42, 50}, {52, 60}, {62, 70}},
			[]header.SACKBlock{{10, 20}, {22, 30}, {32, 40}},
			30,
		},
		{
			[]header.SACKBlock{{10, 20}, {22, 30}, {32, 40}, {42, 50}, {52, 60}, {62, 70}},
			[]header.SACKBlock{{10, 20}, {22, 30}},
			20,
		},
		{
			[]header.SACKBlock{{10, 20}, {22, 30}, {32, 40}, {42, 50}, {52, 60}, {62, 70}},
			[]header.SACKBlock{{10, 20}},
			10,
		},
		{
			[]header.SACKBlock{{10, 20}, {22, 30}, {32, 40}, {42, 50}, {52, 60}, {62, 70}},
			nil,
			8,
		},
		{
			[]header.SACKBlock{{10, 20}, {22, 30}, {32, 40}, {42, 50}, {52, 60}, {62, 70}},
			[]header.SACKBlock{{10, 20}, {22, 30}, {32, 40}, {42, 50}},
			60,
		},
	}
	for _, tc := range testCases {
		b := make([]byte, tc.bufSize)
		t.Logf("testing: %v", tc)
		header.EncodeSACKBlocks(tc.sackBlocks, b)
		opts := header.ParseTCPOptions(b)
		if got, want := opts.SACKBlocks, tc.want; !reflect.DeepEqual(got, want) {
			t.Errorf("header.EncodeSACKBlocks(%v, %v), encoded blocks got: %v, want: %v", tc.sackBlocks, b, got, want)
		}
	}
}

func TestTCPParseOptions(t *testing.T) {
	type tsOption struct {
		tsVal uint32
		tsEcr uint32
	}

	generateOptions := func(tsOpt *tsOption, sackBlocks []header.SACKBlock) []byte {
		l := 0
		if tsOpt != nil {
			l += 10
		}
		if len(sackBlocks) != 0 {
			l += len(sackBlocks)*8 + 2
		}
		b := make([]byte, l)
		offset := 0
		if tsOpt != nil {
			offset = header.EncodeTSOption(tsOpt.tsVal, tsOpt.tsEcr, b)
		}
		header.EncodeSACKBlocks(sackBlocks, b[offset:])
		return b
	}

	testCases := []struct {
		b    []byte
		want header.TCPOptions
	}{
		// Trivial cases.
		{nil, header.TCPOptions{false, 0, 0, nil}},
		{[]byte{header.TCPOptionNOP}, header.TCPOptions{false, 0, 0, nil}},
		{[]byte{header.TCPOptionNOP, header.TCPOptionNOP}, header.TCPOptions{false, 0, 0, nil}},
		{[]byte{header.TCPOptionEOL}, header.TCPOptions{false, 0, 0, nil}},
		{[]byte{header.TCPOptionNOP, header.TCPOptionEOL, header.TCPOptionTS, 10, 1, 1}, header.TCPOptions{false, 0, 0, nil}},

		// Test timestamp parsing.
		{[]byte{header.TCPOptionNOP, header.TCPOptionTS, 10, 0, 0, 0, 1, 0, 0, 0, 1}, header.TCPOptions{true, 1, 1, nil}},
		{[]byte{header.TCPOptionTS, 10, 0, 0, 0, 1, 0, 0, 0, 1}, header.TCPOptions{true, 1, 1, nil}},

		// Test malformed timestamp option.
		{[]byte{header.TCPOptionTS, 8, 1, 1}, header.TCPOptions{false, 0, 0, nil}},
		{[]byte{header.TCPOptionNOP, header.TCPOptionTS, 8, 1, 1}, header.TCPOptions{false, 0, 0, nil}},
		{[]byte{header.TCPOptionNOP, header.TCPOptionTS, 8, 0, 0, 0, 1, 0, 0, 0, 1}, header.TCPOptions{false, 0, 0, nil}},

		// Test SACKBlock parsing.
		{[]byte{header.TCPOptionSACK, 10, 0, 0, 0, 1, 0, 0, 0, 10}, header.TCPOptions{false, 0, 0, []header.SACKBlock{{1, 10}}}},
		{[]byte{header.TCPOptionSACK, 18, 0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0, 11, 0, 0, 0, 12}, header.TCPOptions{false, 0, 0, []header.SACKBlock{{1, 10}, {11, 12}}}},

		// Test malformed SACK option.
		{[]byte{header.TCPOptionSACK, 0}, header.TCPOptions{false, 0, 0, nil}},
		{[]byte{header.TCPOptionSACK, 8, 0, 0, 0, 1, 0, 0, 0, 10}, header.TCPOptions{false, 0, 0, nil}},
		{[]byte{header.TCPOptionSACK, 11, 0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0, 11, 0, 0, 0, 12}, header.TCPOptions{false, 0, 0, nil}},
		{[]byte{header.TCPOptionSACK, 17, 0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0, 11, 0, 0, 0, 12}, header.TCPOptions{false, 0, 0, nil}},
		{[]byte{header.TCPOptionSACK}, header.TCPOptions{false, 0, 0, nil}},
		{[]byte{header.TCPOptionSACK, 10}, header.TCPOptions{false, 0, 0, nil}},
		{[]byte{header.TCPOptionSACK, 10, 0, 0, 0, 1, 0, 0, 0}, header.TCPOptions{false, 0, 0, nil}},

		// Test Timestamp + SACK block parsing.
		{generateOptions(&tsOption{1, 1}, []header.SACKBlock{{1, 10}, {11, 12}}), header.TCPOptions{true, 1, 1, []header.SACKBlock{{1, 10}, {11, 12}}}},
		{generateOptions(&tsOption{1, 2}, []header.SACKBlock{{1, 10}, {11, 12}}), header.TCPOptions{true, 1, 2, []header.SACKBlock{{1, 10}, {11, 12}}}},
		{generateOptions(&tsOption{1, 3}, []header.SACKBlock{{1, 10}, {11, 12}, {13, 14}, {14, 15}, {15, 16}}), header.TCPOptions{true, 1, 3, []header.SACKBlock{{1, 10}, {11, 12}, {13, 14}, {14, 15}}}},

		// Test valid timestamp + malformed SACK block parsing.
		{[]byte{header.TCPOptionTS, 10, 0, 0, 0, 1, 0, 0, 0, 1, header.TCPOptionSACK}, header.TCPOptions{true, 1, 1, nil}},
		{[]byte{header.TCPOptionTS, 10, 0, 0, 0, 1, 0, 0, 0, 1, header.TCPOptionSACK, 10}, header.TCPOptions{true, 1, 1, nil}},
		{[]byte{header.TCPOptionTS, 10, 0, 0, 0, 1, 0, 0, 0, 1, header.TCPOptionSACK, 10, 0, 0, 0}, header.TCPOptions{true, 1, 1, nil}},
		{[]byte{header.TCPOptionTS, 10, 0, 0, 0, 1, 0, 0, 0, 1, header.TCPOptionSACK, 11, 0, 0, 0, 1, 0, 0, 0, 1}, header.TCPOptions{true, 1, 1, nil}},
		{[]byte{header.TCPOptionSACK, header.TCPOptionTS, 10, 0, 0, 0, 1, 0, 0, 0, 1}, header.TCPOptions{false, 0, 0, nil}},
		{[]byte{header.TCPOptionSACK, 10, header.TCPOptionTS, 10, 0, 0, 0, 1, 0, 0, 0, 1}, header.TCPOptions{false, 0, 0, []header.SACKBlock{{134873088, 65536}}}},
		{[]byte{header.TCPOptionSACK, 10, 0, 0, 0, header.TCPOptionTS, 10, 0, 0, 0, 1, 0, 0, 0, 1}, header.TCPOptions{false, 0, 0, []header.SACKBlock{{8, 167772160}}}},
		{[]byte{header.TCPOptionSACK, 11, 0, 0, 0, 1, 0, 0, 0, 1, header.TCPOptionTS, 10, 0, 0, 0, 1, 0, 0, 0, 1}, header.TCPOptions{false, 0, 0, nil}},
	}
	for _, tc := range testCases {
		if got, want := header.ParseTCPOptions(tc.b), tc.want; !reflect.DeepEqual(got, want) {
			t.Errorf("ParseTCPOptions(%v) = %v, want: %v", tc.b, got, tc.want)
		}
	}
}

func TestTCPFlags(t *testing.T) {
	for _, tt := range []struct {
		flags header.TCPFlags
		want  string
	}{
		{header.TCPFlagFin, "F     "},
		{header.TCPFlagSyn, " S    "},
		{header.TCPFlagRst, "  R   "},
		{header.TCPFlagPsh, "   P  "},
		{header.TCPFlagAck, "    A "},
		{header.TCPFlagUrg, "     U"},
		{header.TCPFlagSyn | header.TCPFlagAck, " S  A "},
		{header.TCPFlagFin | header.TCPFlagAck, "F   A "},
	} {
		if got := tt.flags.String(); got != tt.want {
			t.Errorf("got TCPFlags(%#b).String() = %s, want = %s", tt.flags, got, tt.want)
		}
	}
}
