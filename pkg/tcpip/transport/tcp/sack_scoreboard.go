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

package tcp

import (
	"fmt"
	"strings"

	"github.com/google/btree"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/seqnum"
)

// maxSACKBlocks is the maximum number of distinct SACKBlocks the scoreboard
// will track. Once there are 100 distinct blocks, new insertions will fail.
const maxSACKBlocks = 100

// SACKScoreboard stores a set of disjoint SACK ranges.
type SACKScoreboard struct {
	smss      uint16
	maxSACKED seqnum.Value
	sacked    seqnum.Size
	ranges    *btree.BTree
}

// NewSACKScoreboard returns a new SACK Scoreboard.
func NewSACKScoreboard(smss uint16, iss seqnum.Value) *SACKScoreboard {
	return &SACKScoreboard{
		smss:      smss,
		ranges:    btree.New(2),
		maxSACKED: iss,
	}
}

// Insert inserts/merges the provided SACKBlock into the scoreboard.
func (s *SACKScoreboard) Insert(r header.SACKBlock) {
	if s.ranges.Len() >= maxSACKBlocks {
		return
	}

	// Check if we can merge the new range with a range before or after it.
	var toDelete []btree.Item
	if s.maxSACKED.LessThan(r.End - 1) {
		s.maxSACKED = r.End - 1
	}
	s.ranges.AscendGreaterOrEqual(r, func(i btree.Item) bool {
		if i == r {
			return true
		}
		sacked := i.(header.SACKBlock)
		// There is a hole between these two SACK blocks, so we can't
		// merge anymore.
		if r.End.LessThan(r.Start) {
			return false
		}
		// There is some overlap at this point, merge the blocks and
		// delete the other one.
		//
		// ----sS--------sE
		// r.S---------------rE
		//               -------sE
		if sacked.End.LessThan(r.End) {
			// sacked is contained in the newly inserted range.
			// Delete this block.
			toDelete = append(toDelete, i)
			return true
		}
		// sacked covers a range past end of the newly inserted
		// block.
		r.End = sacked.End
		toDelete = append(toDelete, i)
		return true
	})

	s.ranges.DescendLessOrEqual(r, func(i btree.Item) bool {
		if i == r {
			return true
		}
		sacked := i.(header.SACKBlock)
		// sA------sE
		//            rA----rE
		if sacked.End.LessThan(r.Start) {
			return false
		}
		// The previous range extends into the current block. Merge it
		// into the newly inserted range and delete the other one.
		//
		//   <-rA---rE----<---rE--->
		// sA--------------sE
		r.Start = sacked.Start
		// Extend r to cover sacked if sacked extends past r.
		if r.End.LessThan(sacked.End) {
			r.End = sacked.End
		}
		toDelete = append(toDelete, i)
		return true
	})
	for _, i := range toDelete {
		if sb := s.ranges.Delete(i); sb != nil {
			sb := i.(header.SACKBlock)
			s.sacked -= sb.Start.Size(sb.End)
		}
	}

	replaced := s.ranges.ReplaceOrInsert(r)
	if replaced == nil {
		s.sacked += r.Start.Size(r.End)
	}
}

// IsSACKED returns true if the a given range of sequence numbers denoted by r
// are already covered by SACK information in the scoreboard.
func (s *SACKScoreboard) IsSACKED(r header.SACKBlock) bool {
	found := false
	s.ranges.DescendLessOrEqual(r, func(i btree.Item) bool {
		sacked := i.(header.SACKBlock)
		if sacked.End.LessThan(r.Start) {
			return false
		}
		if sacked.Contains(r) {
			found = true
			return false
		}
		return true
	})
	return found
}

// Dump prints the state of the scoreboard structure.
func (s *SACKScoreboard) String() string {
	var str strings.Builder
	str.WriteString("SACKScoreboard: {")
	s.ranges.Ascend(func(i btree.Item) bool {
		str.WriteString(fmt.Sprintf("%v,", i))
		return true
	})
	str.WriteString("}\n")
	return str.String()
}

// Delete removes all SACK information prior to seq.
func (s *SACKScoreboard) Delete(seq seqnum.Value) {
	toDelete := []btree.Item{}
	r := header.SACKBlock{seq, seq.Add(1)}
	s.ranges.DescendLessOrEqual(r, func(i btree.Item) bool {
		if i == r {
			return true
		}
		sb := i.(header.SACKBlock)
		toDelete = append(toDelete, i)
		if sb.End.LessThanEq(seq) {
			s.sacked -= sb.Start.Size(sb.End)
		} else {
			newSB := header.SACKBlock{seq, sb.End}
			s.ranges.ReplaceOrInsert(newSB)
			s.sacked -= sb.Start.Size(seq)
		}
		return true
	})
	for _, i := range toDelete {
		s.ranges.Delete(i)
	}
}

// Copy provides a copy of the SACK scoreboard.
func (s *SACKScoreboard) Copy() (sackBlocks []header.SACKBlock, maxSACKED seqnum.Value) {
	s.ranges.Ascend(func(i btree.Item) bool {
		sackBlocks = append(sackBlocks, i.(header.SACKBlock))
		return true
	})
	return sackBlocks, s.maxSACKED
}

// IsLost implements the IsLost(SeqNum) operation defined in RFC 3517 section 4.
//
// This routine returns whether the given sequence number is considered to be
// lost. The routine returns true when either nDupAckThreshold discontiguous
// SACKed sequences have arrived above 'SeqNum' or (nDupAckThreshold * SMSS)
// bytes with sequence numbers greater than 'SeqNum' have been SACKed.
// Otherwise, the routine returns false.
func (s *SACKScoreboard) IsLost(r header.SACKBlock) bool {
	nDupSACK := 0
	nDupSACKBytes := seqnum.Size(0)
	isLost := false
	s.ranges.AscendGreaterOrEqual(r, func(i btree.Item) bool {
		sacked := i.(header.SACKBlock)
		if sacked.Contains(r) {
			return false
		}
		nDupSACKBytes += sacked.Start.Size(sacked.End)
		nDupSACK++
		if nDupSACK >= nDupAckThreshold || nDupSACKBytes >= seqnum.Size(nDupAckThreshold*s.smss) {
			isLost = true
			return false
		}
		return true
	})
	return isLost
}

// Empty returns true if the SACK scoreboard has no entries, false otherwise.
func (s *SACKScoreboard) Empty() bool {
	return s.ranges.Len() == 0
}

// Sacked returns the current number of bytes held in the SACK scoreboard.
func (s *SACKScoreboard) Sacked() seqnum.Size {
	return s.sacked
}

// MaxSACKED returns the highest sequence number ever inserted in the SACK
// scoreboard.
func (s *SACKScoreboard) MaxSACKED() seqnum.Value {
	return s.maxSACKED
}
