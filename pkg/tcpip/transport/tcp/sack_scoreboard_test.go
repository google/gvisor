// Copyright 2026 The gVisor Authors.
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

package tcp

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// buildScoreboard creates a SACKScoreboard pre-populated with n disjoint SACK
// blocks starting at iss. Each block covers [start, start+blockSize) with a
// gap of gapSize bytes between blocks, simulating selective ACKs under packet
// loss.
func buildScoreboard(iss seqnum.Value, smss uint16, n int, blockSize, gapSize seqnum.Size) *SACKScoreboard {
	s := NewSACKScoreboard(smss, iss)
	seq := iss
	for i := 0; i < n; i++ {
		// Skip a gap (the "lost" segment), then insert a SACK block.
		seq = seq.Add(gapSize)
		s.Insert(header.SACKBlock{Start: seq, End: seq.Add(blockSize)})
		seq = seq.Add(blockSize)
	}
	return s
}

// BenchmarkIsSACKED measures allocations in the IsSACKED hot path.
// Each call traverses the btree via DescendLessOrEqual, which boxes
// header.SACKBlock into btree.Item on every callback invocation.
func BenchmarkIsSACKED(b *testing.B) {
	const (
		iss       seqnum.Value = 0
		smss      uint16       = 1460
		nBlocks                = 30
		blockSize seqnum.Size  = 1460
		gapSize   seqnum.Size  = 1460
	)
	s := buildScoreboard(iss, smss, nBlocks, blockSize, gapSize)

	// Query a range that falls in the middle of the scoreboard so the
	// btree actually has to descend into it.
	mid := iss.Add(seqnum.Size(nBlocks) * (blockSize + gapSize) / 2)
	query := header.SACKBlock{Start: mid, End: mid.Add(blockSize)}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.IsSACKED(query)
	}
}

// BenchmarkIsRangeLost measures allocations in IsRangeLost.
// This path does both DescendLessOrEqual and AscendGreaterOrEqual,
// boxing on every callback.
func BenchmarkIsRangeLost(b *testing.B) {
	const (
		iss       seqnum.Value = 0
		smss      uint16       = 1460
		nBlocks                = 30
		blockSize seqnum.Size  = 1460
		gapSize   seqnum.Size  = 1460
	)
	s := buildScoreboard(iss, smss, nBlocks, blockSize, gapSize)

	// Query a gap (unsacked region) so IsRangeLost has to scan
	// multiple SACK blocks above to determine loss.
	gapStart := iss.Add((blockSize + gapSize) * 5) // start of 6th gap
	query := header.SACKBlock{Start: gapStart, End: gapStart.Add(gapSize)}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.IsRangeLost(query)
	}
}

// BenchmarkInsert measures allocations from Insert, which performs
// AscendGreaterOrEqual + DescendLessOrEqual + ReplaceOrInsert, each
// boxing SACKBlock into btree.Item.
func BenchmarkInsert(b *testing.B) {
	const (
		iss  seqnum.Value = 0
		smss uint16       = 1460
	)
	// Pre-populate with a modest scoreboard.
	s := buildScoreboard(iss, smss, 20, 1460, 1460)

	// Insert a block that overlaps with existing ranges, triggering
	// merge logic (ascend + descend + delete + insert).
	block := header.SACKBlock{
		Start: iss.Add(1460 * 9),  // overlaps ~5th gap
		End:   iss.Add(1460 * 12), // spans into existing block
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Insert(block)
	}
}

// BenchmarkDelete measures allocations from Delete, which uses
// DescendLessOrEqual + Delete + ReplaceOrInsert.
func BenchmarkDelete(b *testing.B) {
	const (
		iss       seqnum.Value = 0
		smss      uint16       = 1460
		nBlocks                = 30
		blockSize seqnum.Size  = 1460
		gapSize   seqnum.Size  = 1460
	)

	// Pre-build all scoreboards to avoid StopTimer/StartTimer overhead.
	boards := make([]*SACKScoreboard, b.N)
	for i := range boards {
		boards[i] = buildScoreboard(iss, smss, nBlocks, blockSize, gapSize)
	}
	seq := iss.Add(seqnum.Size(nBlocks) * (blockSize + gapSize) / 2)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		boards[i].Delete(seq)
	}
}

// BenchmarkSetPipeWorkload simulates the SetPipe hot loop from the
// issue's pprof: for every unacked segment, call IsSACKED and
// IsRangeLost in sequence. This is the pattern that caused 1.4 GB of
// allocations in 30 seconds in the reporter's production workload.
func BenchmarkSetPipeWorkload(b *testing.B) {
	const (
		iss       seqnum.Value = 0
		smss      uint16       = 1460
		nBlocks                = 30
		blockSize seqnum.Size  = 1460
		gapSize   seqnum.Size  = 1460
	)
	s := buildScoreboard(iss, smss, nBlocks, blockSize, gapSize)

	total := seqnum.Size(nBlocks) * (blockSize + gapSize)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Walk through every MSS-sized segment in the range, calling
		// IsSACKED and IsRangeLost for each, as SetPipe does.
		for off := seqnum.Size(0); off < total; off += seqnum.Size(smss) {
			seg := header.SACKBlock{
				Start: iss.Add(off),
				End:   iss.Add(off + seqnum.Size(smss)),
			}
			s.IsSACKED(seg)
			s.IsRangeLost(seg)
		}
	}
}
