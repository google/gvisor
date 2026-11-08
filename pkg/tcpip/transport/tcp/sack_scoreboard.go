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

package tcp

import (
	"fmt"
	"strings"

	"github.com/google/btree"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

const (
	// maxSACKBlocks is the maximum number of distinct SACKBlocks the
	// scoreboard will track. Once there are 100 distinct blocks, new
	// insertions will fail.
	maxSACKBlocks = 100

	// defaultBtreeDegree is set to 2 as btree.New(2) results in a 2-3-4
	// tree.
	defaultBtreeDegree = 2
)

// sackBlockLess is the comparison function for BTreeG, replacing the
// btree.Item interface method.
func sackBlockLess(a, b header.SACKBlock) bool {
	return a.Start.LessThan(b.Start)
}

// SACKScoreboard stores a set of disjoint SACK ranges.
//
// +stateify savable
type SACKScoreboard struct {
	// smss is defined in RFC5681 as following:
	//
	//    The SMSS is the size of the largest segment that the sender can
	//    transmit.  This value can be based on the maximum transmission unit
	//    of the network, the path MTU discovery [RFC1191, RFC4821] algorithm,
	//    RMSS (see next item), or other factors.  The size does not include
	//    the TCP/IP headers and options.
	smss uint16
	// initialMSS bounds the wire units that may remain in the queue
	// after a path MTU reduction. The sender never raises its MSS.
	initialMSS uint16
	maxSACKED  seqnum.Value
	sacked     seqnum.Size                     `state:"nosave"`
	ranges     *btree.BTreeG[header.SACKBlock] `state:"nosave"`
}

// NewSACKScoreboard returns a new SACK Scoreboard.
func NewSACKScoreboard(smss uint16, iss seqnum.Value) *SACKScoreboard {
	return &SACKScoreboard{
		smss:       smss,
		initialMSS: smss,
		ranges:     btree.NewG[header.SACKBlock](defaultBtreeDegree, sackBlockLess),
		maxSACKED:  iss,
	}
}

// Reset erases all known range information from the SACK scoreboard.
func (s *SACKScoreboard) Reset() {
	s.ranges = btree.NewG[header.SACKBlock](defaultBtreeDegree, sackBlockLess)
	s.sacked = 0
}

// Insert merges r with the scoreboard and returns the resulting range.
// The empty range means the scoreboard was full.
func (s *SACKScoreboard) Insert(r header.SACKBlock) header.SACKBlock {
	if s.ranges.Len() >= maxSACKBlocks {
		return header.SACKBlock{}
	}

	// Check if we can merge the new range with a range before or after it.
	var toDelete []header.SACKBlock
	if s.maxSACKED.LessThan(r.End - 1) {
		s.maxSACKED = r.End - 1
	}
	s.ranges.AscendGreaterOrEqual(r, func(sacked header.SACKBlock) bool {
		if sacked == r {
			return true
		}
		// There is a hole between these two SACK blocks, so we can't
		// merge anymore.
		if r.End.LessThan(sacked.Start) {
			return false
		}
		// There is some overlap at this point, merge the blocks and
		// delete the other one.
		//
		//	----sS--------sE
		//	r.S---------------rE
		//	              -------sE
		if sacked.End.LessThan(r.End) {
			// sacked is contained in the newly inserted range.
			// Delete this block.
			toDelete = append(toDelete, sacked)
			return true
		}
		// sacked covers a range past end of the newly inserted
		// block.
		r.End = sacked.End
		toDelete = append(toDelete, sacked)
		return true
	})

	s.ranges.DescendLessOrEqual(r, func(sacked header.SACKBlock) bool {
		if sacked == r {
			return true
		}
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
		toDelete = append(toDelete, sacked)
		return true
	})
	for _, sb := range toDelete {
		if _, ok := s.ranges.Delete(sb); ok {
			s.sacked -= sb.Start.Size(sb.End)
		}
	}

	_, replaced := s.ranges.ReplaceOrInsert(r)
	if !replaced {
		s.sacked += r.Start.Size(r.End)
	}
	return r
}

// creditEnd bounds the part of an existing SACK range that newly received
// bytes can complete. No wire unit ends more than one MSS after those bytes.
func (s *SACKScoreboard) creditEnd(end, mergedEnd seqnum.Value) seqnum.Value {
	return end.Add(min(end.Size(mergedEnd), seqnum.Size(s.initialMSS)-1))
}

// IsSACKED returns true if the a given range of sequence numbers denoted by r
// are already covered by SACK information in the scoreboard.
func (s *SACKScoreboard) IsSACKED(r header.SACKBlock) bool {
	if s.Empty() {
		return false
	}

	found := false
	s.ranges.DescendLessOrEqual(r, func(sacked header.SACKBlock) bool {
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

// packetRun contains the transmitted units whose final bytes belong to a
// queue entry. Splitting that entry does not create another wire packet.
type packetRun struct {
	block header.SACKBlock
	mss   seqnum.Size
	count int
}

func (s *segment) sackPackets() packetRun {
	b := s.sackBlock()
	mss := seqnum.Size(s.gsoMSS)
	if mss == 0 {
		// Entries constructed without a recorded transmission contain one
		// unit. Production transmit records a size for every sent packet.
		return packetRun{b, b.Start.Size(b.End), 1}
	}
	first := s.gsoStart.Size(b.Start) / mss
	last := s.gsoStart.Size(b.End)
	if s.truncatedTail {
		last -= last % mss
	}
	// The last short packet of a real transmission owns its endpoint too.
	n := (last+mss-1)/mss - first
	return packetRun{header.SACKBlock{
		Start: s.gsoStart.Add(first * mss),
		End:   s.gsoStart.Add(last),
	}, mss, int(n)}
}

// covered counts whole transmitted units, including one whose prefix was
// cumulatively acknowledged, without visiting each MSS of a large GSO.
func (p packetRun) covered(r header.SACKBlock, una seqnum.Value) int {
	start := p.block.Start
	if start.LessThan(una) {
		start = una
	}
	if !start.LessThan(r.End) || !r.Start.LessThan(p.block.End) {
		return 0
	}
	first, last := 0, p.count
	if start.LessThan(r.Start) {
		first = int((p.block.Start.Size(r.Start) + p.mss - 1) / p.mss)
	}
	if r.End.LessThan(p.block.End) {
		last = int(p.block.Start.Size(r.End) / p.mss)
	}
	return max(0, last-first)
}

// sackedPackets accounts for units reported across several disjoint ranges.
func (s *SACKScoreboard) sackedPackets(p packetRun, una seqnum.Value, known header.SACKBlock) int {
	if p.count == 0 {
		return 0
	}
	if known.Start != known.End && p.covered(known, una) == p.count {
		return p.count
	}
	n := 0
	s.ranges.DescendLessOrEqual(header.SACKBlock{Start: p.block.End - 1}, func(r header.SACKBlock) bool {
		n += p.covered(r, una)
		return p.block.Start.LessThan(r.Start) && una.LessThan(r.Start)
	})
	return n
}

// String returns human-readable state of the scoreboard structure.
func (s *SACKScoreboard) String() string {
	var str strings.Builder
	str.WriteString("SACKScoreboard: {")
	s.ranges.Ascend(func(sb header.SACKBlock) bool {
		fmt.Fprintf(&str, "%v,", sb)
		return true
	})
	str.WriteString("}\n")
	return str.String()
}

// Delete removes all SACK information prior to seq.
func (s *SACKScoreboard) Delete(seq seqnum.Value) {
	if s.Empty() {
		return
	}
	var toDelete []header.SACKBlock
	var toInsert []header.SACKBlock
	r := header.SACKBlock{seq, seq.Add(1)}
	s.ranges.DescendLessOrEqual(r, func(sb header.SACKBlock) bool {
		if sb == r {
			return true
		}
		toDelete = append(toDelete, sb)
		if sb.End.LessThanEq(seq) {
			s.sacked -= sb.Start.Size(sb.End)
		} else {
			newSB := header.SACKBlock{seq, sb.End}
			toInsert = append(toInsert, newSB)
			s.sacked -= sb.Start.Size(seq)
		}
		return true
	})
	for _, sb := range toDelete {
		s.ranges.Delete(sb)
	}
	for _, sb := range toInsert {
		s.ranges.ReplaceOrInsert(sb)
	}
}

// Copy provides a copy of the SACK scoreboard.
func (s *SACKScoreboard) Copy() (sackBlocks []header.SACKBlock, maxSACKED seqnum.Value) {
	s.ranges.Ascend(func(sb header.SACKBlock) bool {
		sackBlocks = append(sackBlocks, sb)
		return true
	})
	return sackBlocks, s.maxSACKED
}

// IsRangeLost implements the IsLost(SeqNum) operation defined in RFC 6675
// section 4 but operates on a range of sequence numbers and returns true if
// there are at least nDupAckThreshold SACK blocks greater than the range being
// checked or if more than (nDupAckThreshold-1)*s.smss bytes have been SACKED
// with sequence numbers greater than the block being checked.
func (s *SACKScoreboard) IsRangeLost(r header.SACKBlock) bool {
	if s.Empty() {
		return false
	}
	nDupSACK := 0
	nDupSACKBytes := seqnum.Size(0)
	isLost := false

	// We need to check if the immediate lower (if any) sacked
	// range contains or partially overlaps with r.
	searchMore := true
	s.ranges.DescendLessOrEqual(r, func(sacked header.SACKBlock) bool {
		if sacked.Contains(r) {
			searchMore = false
			return false
		}
		if sacked.End.LessThanEq(r.Start) {
			// all sequence numbers covered by sacked are below
			// r so we continue searching.
			return false
		}
		// There is a partial overlap. In this case we r.Start is
		// between sacked.Start & sacked.End and r.End extends beyond
		// sacked.End.
		// Move r.Start to sacked.End and continuing searching blocks
		// above r.Start.
		r.Start = sacked.End
		return false
	})

	if !searchMore {
		return isLost
	}

	s.ranges.AscendGreaterOrEqual(r, func(sacked header.SACKBlock) bool {
		if sacked.Contains(r) {
			return false
		}
		nDupSACKBytes += sacked.Start.Size(sacked.End)
		nDupSACK++
		if nDupSACK >= nDupAckThreshold || nDupSACKBytes > (nDupAckThreshold-1)*seqnum.Size(s.smss) {
			isLost = true
			return false
		}
		return true
	})
	return isLost
}

// IsLost implements the IsLost(SeqNum) operation defined in RFC 6675 section 4.
// See IsRangeLost for the loss thresholds.
func (s *SACKScoreboard) IsLost(seq seqnum.Value) bool {
	return s.IsRangeLost(header.SACKBlock{seq, seq.Add(1)})
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

// SMSS returns the sender's MSS as held by the SACK scoreboard.
func (s *SACKScoreboard) SMSS() uint16 {
	return s.smss
}
