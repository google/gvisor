// Copyright 2018 Google LLC
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

	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/seqnum"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp"
)

const smss = 1500

func initScoreboard(blocks []header.SACKBlock, iss seqnum.Value) *tcp.SACKScoreboard {
	s := tcp.NewSACKScoreboard(smss, iss)
	for _, blk := range blocks {
		s.Insert(blk)
	}
	return s
}

func TestSACKScoreboardIsSACKED(t *testing.T) {
	type blockTest struct {
		block  header.SACKBlock
		sacked bool
	}
	testCases := []struct {
		comment          string
		scoreboardBlocks []header.SACKBlock
		blockTests       []blockTest
		iss              seqnum.Value
	}{
		{
			"Test holes and unsacked SACK blocks in SACKed ranges and insertion of overlapping SACK blocks",
			[]header.SACKBlock{{10, 20}, {10, 30}, {30, 40}, {41, 50}, {5, 10}, {1, 50}, {111, 120}, {101, 110}, {52, 120}},
			[]blockTest{
				{header.SACKBlock{15, 21}, true},
				{header.SACKBlock{200, 201}, false},
				{header.SACKBlock{50, 51}, false},
				{header.SACKBlock{53, 120}, true},
			},
			0,
		},
		{
			"Test disjoint SACKBlocks",
			[]header.SACKBlock{{2288624809, 2288810057}, {2288811477, 2288838565}},
			[]blockTest{
				{header.SACKBlock{2288624809, 2288810057}, true},
				{header.SACKBlock{2288811477, 2288838565}, true},
				{header.SACKBlock{2288810057, 2288811477}, false},
			},
			2288624809,
		},
		{
			"Test sequence number wrap around",
			[]header.SACKBlock{{4294254144, 225652}, {5340409, 5350509}},
			[]blockTest{
				{header.SACKBlock{4294254144, 4294254145}, true},
				{header.SACKBlock{4294254143, 4294254144}, false},
				{header.SACKBlock{4294254144, 1}, true},
				{header.SACKBlock{225652, 5350509}, false},
				{header.SACKBlock{5340409, 5350509}, true},
				{header.SACKBlock{5350509, 5350609}, false},
			},
			4294254144,
		},
	}
	for _, tc := range testCases {
		sb := initScoreboard(tc.scoreboardBlocks, tc.iss)
		for _, blkTest := range tc.blockTests {
			if want, got := blkTest.sacked, sb.IsSACKED(blkTest.block); got != want {
				t.Errorf("%s: s.IsSACKED(%v) = %v, want %v", tc.comment, blkTest.block, got, want)
			}
		}
	}
}

func TestSACKScoreboardIsLost(t *testing.T) {
	s := tcp.NewSACKScoreboard(10, 0)
	s.Insert(header.SACKBlock{1, 50})
	s.Insert(header.SACKBlock{51, 100})
	s.Insert(header.SACKBlock{111, 120})
	s.Insert(header.SACKBlock{101, 110})
	s.Insert(header.SACKBlock{121, 141})
	testCases := []struct {
		block header.SACKBlock
		lost  bool
	}{
		{block: header.SACKBlock{0, 1}, lost: true},
		{block: header.SACKBlock{1, 2}, lost: false},
		{block: header.SACKBlock{1, 45}, lost: false},
		{block: header.SACKBlock{50, 51}, lost: true},
		// This one should return true because there are
		// > (nDupAckThreshold - 1) * 10 (smss) bytes that have been sacked above
		// this sequence number.
		{block: header.SACKBlock{119, 120}, lost: true},
		{block: header.SACKBlock{120, 121}, lost: true},
		{block: header.SACKBlock{125, 126}, lost: false},
	}
	for _, tc := range testCases {
		if want, got := tc.lost, s.IsLost(tc.block); got != want {
			t.Errorf("s.IsLost(%v) = %v, want %v", tc.block, got, want)
		}
	}
}

func TestSACKScoreboardDelete(t *testing.T) {
	blocks := []header.SACKBlock{{4294254144, 225652}, {5340409, 5350509}}
	s := initScoreboard(blocks, 4294254143)
	s.Delete(5340408)
	if s.Empty() {
		t.Fatalf("s.Empty() = true, want false")
	}
	if got, want := s.Sacked(), blocks[1].Start.Size(blocks[1].End); got != want {
		t.Fatalf("incorrect sacked bytes in scoreboard got: %v, want: %v", got, want)
	}
	s.Delete(5340410)
	if s.Empty() {
		t.Fatal("s.Empty() = true, want false")
	}
	newSB := header.SACKBlock{5340410, 5350509}
	if !s.IsSACKED(newSB) {
		t.Fatalf("s.IsSACKED(%v) = false, want true, scoreboard: %v", newSB, s)
	}
	s.Delete(5350509)
	lastOctet := header.SACKBlock{5350508, 5350509}
	if s.IsSACKED(lastOctet) {
		t.Fatalf("s.IsSACKED(%v) = false, want true", lastOctet)
	}

	s.Delete(5350510)
	if !s.Empty() {
		t.Fatal("s.Empty() = false, want true")
	}
	if got, want := s.Sacked(), seqnum.Size(0); got != want {
		t.Fatalf("incorrect sacked bytes in scoreboard got: %v, want: %v", got, want)
	}
}
