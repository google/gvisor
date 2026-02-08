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

// Package segment provides tools for working with collections of segments. A
// segment is a key-value mapping, where the key is a non-empty contiguous
// range of values of type Key, and the value is a single value of type Value.
//
// Clients using this package must use the go_template_instance rule in
// tools/go_generics/defs.bzl to create an instantiation of this
// template package, providing types to use in place of Key, Range, Value, and
// Functions. See pkg/segment/test/BUILD for a usage example.
package segment

import (
	"bytes"
	"fmt"
)

// Key is a required type parameter that must be an integral type.
type Key uint64

// Range is a required type parameter equivalent to Range<Key>.
type Range any

// Value is a required type parameter.
type Value any

// trackGaps is an optional parameter.
//
// If trackGaps is 1, the Set will track maximum gap size recursively,
// enabling the GapIterator.{Prev,Next}LargeEnoughGap functions. In this
// case, Key must be an unsigned integer.
//
// trackGaps must be 0 or 1.
const trackGaps = 0

var _ = uint8(trackGaps << 7) // Will fail if not zero or one.

// dynamicGap is a type that disappears if trackGaps is 0.
type dynamicGap [trackGaps]Key

// Get returns the value of the gap.
//
// Precondition: trackGaps must be non-zero.
func (d *dynamicGap) Get() Key {
	return d[:][0]
}

// Set sets the value of the gap.
//
// Precondition: trackGaps must be non-zero.
func (d *dynamicGap) Set(v Key) {
	d[:][0] = v
}

// Functions is a required type parameter that must be a struct implementing
// the methods defined by Functions.
type Functions interface {
	// MinKey returns the minimum allowed key.
	MinKey() Key

	// MaxKey returns the maximum allowed key + 1.
	MaxKey() Key

	// ClearValue deinitializes the given value. (For example, if Value is a
	// pointer or interface type, ClearValue should set it to nil.)
	ClearValue(*Value)

	// Merge attempts to merge the values corresponding to two consecutive
	// segments. If successful, Merge returns (merged value, true). Otherwise,
	// it returns (unspecified, false).
	//
	// Preconditions: r1.End == r2.Start.
	//
	// Postconditions: If merging succeeds, val1 and val2 are invalidated.
	Merge(r1 Range, val1 Value, r2 Range, val2 Value) (Value, bool)

	// Split splits a segment's value at a key within its range, such that the
	// first returned value corresponds to the range [r.Start, split) and the
	// second returned value corresponds to the range [split, r.End).
	//
	// Preconditions: r.Start < split < r.End.
	//
	// Postconditions: The original value val is invalidated.
	Split(r Range, val Value, split Key) (Value, Value)
}

const (
	// minDegree is the minimum degree of an internal node in a Set B-tree.
	//
	//	- Any non-root node has at least minDegree-1 segments.
	//
	//	- Any non-root internal (non-leaf) node has at least minDegree children.
	//
	//	- The root node may have fewer than minDegree-1 segments, but it may
	// only have 0 segments if the tree is empty.
	//
	// Our implementation requires minDegree >= 3. Higher values of minDegree
	// usually improve performance, but increase memory usage for small sets.
	minDegree = 3

	maxDegree = 2 * minDegree
)

// A Set is a mapping of segments with non-overlapping Range keys. The zero
// value for a Set is an empty set. Set values are not safely movable nor
// copyable. Set is thread-compatible.
//
// +stateify savable
type Set struct {
	root node `state:".([]FlatSegment)"`
}

// IsEmpty returns true if the set contains no segments.
func (s *Set) IsEmpty() bool {
	return s.root.nrSegments == 0
}

// IsEmptyRange returns true iff no segments in the set overlap the given
// range. This is semantically equivalent to s.SpanRange(r) == 0, but may be
// more efficient.
func (s *Set) IsEmptyRange(r Range) bool {
	switch {
	case r.Length() < 0:
		panic(fmt.Sprintf("invalid range %v", r))
	case r.Length() == 0:
		return true
	}
	_, gap := s.Find(r.Start)
	if !gap.Ok() {
		return false
	}
	return r.End <= gap.End()
}

// Span returns the total size of all segments in the set.
func (s *Set) Span() Key {
	var sz Key
	for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		sz += seg.Range().Length()
	}
	return sz
}

// SpanRange returns the total size of the intersection of segments in the set
// with the given range.
func (s *Set) SpanRange(r Range) Key {
	switch {
	case r.Length() < 0:
		panic(fmt.Sprintf("invalid range %v", r))
	case r.Length() == 0:
		return 0
	}
	var sz Key
	for seg := s.LowerBoundSegment(r.Start); seg.Ok() && seg.Start() < r.End; seg = seg.NextSegment() {
		sz += seg.Range().Intersect(r).Length()
	}
	return sz
}

// FirstSegment returns the first segment in the set. If the set is empty,
// FirstSegment returns a terminal iterator.
func (s *Set) FirstSegment() Iterator {
	if s.root.nrSegments == 0 {
		return Iterator{}
	}
	return s.root.firstSegment()
}

// LastSegment returns the last segment in the set. If the set is empty,
// LastSegment returns a terminal iterator.
func (s *Set) LastSegment() Iterator {
	if s.root.nrSegments == 0 {
		return Iterator{}
	}
	return s.root.lastSegment()
}

// FirstGap returns the first gap in the set.
func (s *Set) FirstGap() GapIterator {
	n := &s.root
	for n.hasChildren {
		n = n.children[0]
	}
	return GapIterator{n, 0}
}

// LastGap returns the last gap in the set.
func (s *Set) LastGap() GapIterator {
	n := &s.root
	for n.hasChildren {
		n = n.children[n.nrSegments]
	}
	return GapIterator{n, n.nrSegments}
}

// Find returns the segment or gap whose range contains the given key. If a
// segment is found, the returned Iterator is non-terminal and the
// returned GapIterator is terminal. Otherwise, the returned Iterator is
// terminal and the returned GapIterator is non-terminal.
func (s *Set) Find(key Key) (Iterator, GapIterator) {
	n := &s.root
	for {
		// Binary search invariant: the correct value of i lies within [lower,
		// upper].
		lower := 0
		upper := n.nrSegments
		for lower < upper {
			i := lower + (upper-lower)/2
			if r := n.keys[i]; key < r.End {
				if key >= r.Start {
					return Iterator{n, i}, GapIterator{}
				}
				upper = i
			} else {
				lower = i + 1
			}
		}
		i := lower
		if !n.hasChildren {
			return Iterator{}, GapIterator{n, i}
		}
		n = n.children[i]
	}
}

// FindSegment returns the segment whose range contains the given key. If no
// such segment exists, FindSegment returns a terminal iterator.
func (s *Set) FindSegment(key Key) Iterator {
	seg, _ := s.Find(key)
	return seg
}

// LowerBoundSegment returns the segment with the lowest range that contains a
// key greater than or equal to min. If no such segment exists,
// LowerBoundSegment returns a terminal iterator.
func (s *Set) LowerBoundSegment(min Key) Iterator {
	seg, gap := s.Find(min)
	if seg.Ok() {
		return seg
	}
	return gap.NextSegment()
}

// UpperBoundSegment returns the segment with the highest range that contains a
// key less than or equal to max. If no such segment exists, UpperBoundSegment
// returns a terminal iterator.
func (s *Set) UpperBoundSegment(max Key) Iterator {
	seg, gap := s.Find(max)
	if seg.Ok() {
		return seg
	}
	return gap.PrevSegment()
}

// FindGap returns the gap containing the given key. If no such gap exists
// (i.e. the set contains a segment containing that key), FindGap returns a
// terminal iterator.
func (s *Set) FindGap(key Key) GapIterator {
	_, gap := s.Find(key)
	return gap
}

// LowerBoundGap returns the gap with the lowest range that is greater than or
// equal to min.
func (s *Set) LowerBoundGap(min Key) GapIterator {
	seg, gap := s.Find(min)
	if gap.Ok() {
		return gap
	}
	return seg.NextGap()
}

// UpperBoundGap returns the gap with the highest range that is less than or
// equal to max.
func (s *Set) UpperBoundGap(max Key) GapIterator {
	seg, gap := s.Find(max)
	if gap.Ok() {
		return gap
	}
	return seg.PrevGap()
}

// FirstLargeEnoughGap returns the first gap in the set with at least the given
// length. If no such gap exists, FirstLargeEnoughGap returns a terminal
// iterator.
//
// Precondition: trackGaps must be 1.
func (s *Set) FirstLargeEnoughGap(minSize Key) GapIterator {
	if trackGaps != 1 {
		panic("set is not tracking gaps")
	}
	gap := s.FirstGap()
	if gap.Range().Length() >= minSize {
		return gap
	}
	return gap.NextLargeEnoughGap(minSize)
}

// LastLargeEnoughGap returns the last gap in the set with at least the given
// length. If no such gap exists, LastLargeEnoughGap returns a terminal
// iterator.
//
// Precondition: trackGaps must be 1.
func (s *Set) LastLargeEnoughGap(minSize Key) GapIterator {
	if trackGaps != 1 {
		panic("set is not tracking gaps")
	}
	gap := s.LastGap()
	if gap.Range().Length() >= minSize {
		return gap
	}
	return gap.PrevLargeEnoughGap(minSize)
}

// LowerBoundLargeEnoughGap returns the first gap in the set with at least the
// given length and whose range contains a key greater than or equal to min. If
// no such gap exists, LowerBoundLargeEnoughGap returns a terminal iterator.
//
// Precondition: trackGaps must be 1.
func (s *Set) LowerBoundLargeEnoughGap(min, minSize Key) GapIterator {
	if trackGaps != 1 {
		panic("set is not tracking gaps")
	}
	gap := s.LowerBoundGap(min)
	if gap.Range().Length() >= minSize {
		return gap
	}
	return gap.NextLargeEnoughGap(minSize)
}

// UpperBoundLargeEnoughGap returns the last gap in the set with at least the
// given length and whose range contains a key less than or equal to max. If no
// such gap exists, UpperBoundLargeEnoughGap returns a terminal iterator.
//
// Precondition: trackGaps must be 1.
func (s *Set) UpperBoundLargeEnoughGap(max, minSize Key) GapIterator {
	if trackGaps != 1 {
		panic("set is not tracking gaps")
	}
	gap := s.UpperBoundGap(max)
	if gap.Range().Length() >= minSize {
		return gap
	}
	return gap.PrevLargeEnoughGap(minSize)
}

// Insert inserts the given segment into the given gap. If the new segment can
// be merged with adjacent segments, Insert will do so. Insert returns an
// iterator to the segment containing the inserted value (which may have been
// merged with other values). All existing iterators (including gap, but not
// including the returned iterator) are invalidated.
//
// If the gap cannot accommodate the segment, or if r is invalid, Insert panics.
//
// Insert is semantically equivalent to a InsertWithoutMerging followed by a
// Merge, but may be more efficient. Note that there is no unchecked variant of
// Insert since Insert must retrieve and inspect gap's predecessor and
// successor segments regardless.
func (s *Set) Insert(gap GapIterator, r Range, val Value) Iterator {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	prev, next := gap.PrevSegment(), gap.NextSegment()
	if prev.Ok() && prev.End() > r.Start {
		panic(fmt.Sprintf("new segment %v overlaps predecessor %v", r, prev.Range()))
	}
	if next.Ok() && next.Start() < r.End {
		panic(fmt.Sprintf("new segment %v overlaps successor %v", r, next.Range()))
	}
	if prev.Ok() && prev.End() == r.Start {
		if mval, ok := (Functions{}).Merge(prev.Range(), prev.Value(), r, val); ok {
			shrinkMaxGap := trackGaps != 0 && gap.Range().Length() == gap.node.maxGap.Get()
			prev.SetEndUnchecked(r.End)
			prev.SetValue(mval)
			if shrinkMaxGap {
				gap.node.updateMaxGapLeaf()
			}
			if next.Ok() && next.Start() == r.End {
				val = mval
				if mval, ok := (Functions{}).Merge(prev.Range(), val, next.Range(), next.Value()); ok {
					prev.SetEndUnchecked(next.End())
					prev.SetValue(mval)
					return s.Remove(next).PrevSegment()
				}
			}
			return prev
		}
	}
	if next.Ok() && next.Start() == r.End {
		if mval, ok := (Functions{}).Merge(r, val, next.Range(), next.Value()); ok {
			shrinkMaxGap := trackGaps != 0 && gap.Range().Length() == gap.node.maxGap.Get()
			next.SetStartUnchecked(r.Start)
			next.SetValue(mval)
			if shrinkMaxGap {
				gap.node.updateMaxGapLeaf()
			}
			return next
		}
	}
	// InsertWithoutMergingUnchecked will maintain maxGap if necessary.
	return s.InsertWithoutMergingUnchecked(gap, r, val)
}

// InsertWithoutMerging inserts the given segment into the given gap and
// returns an iterator to the inserted segment. All existing iterators
// (including gap, but not including the returned iterator) are invalidated.
//
// If the gap cannot accommodate the segment, or if r is invalid,
// InsertWithoutMerging panics.
func (s *Set) InsertWithoutMerging(gap GapIterator, r Range, val Value) Iterator {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	if gr := gap.Range(); !gr.IsSupersetOf(r) {
		panic(fmt.Sprintf("cannot insert segment range %v into gap range %v", r, gr))
	}
	return s.InsertWithoutMergingUnchecked(gap, r, val)
}

// InsertWithoutMergingUnchecked inserts the given segment into the given gap
// and returns an iterator to the inserted segment. All existing iterators
// (including gap, but not including the returned iterator) are invalidated.
//
// Preconditions:
//   - r.Start >= gap.Start().
//   - r.End <= gap.End().
func (s *Set) InsertWithoutMergingUnchecked(gap GapIterator, r Range, val Value) Iterator {
	gap = gap.node.rebalanceBeforeInsert(gap)
	splitMaxGap := trackGaps != 0 && (gap.node.nrSegments == 0 || gap.Range().Length() == gap.node.maxGap.Get())
	copy(gap.node.keys[gap.index+1:], gap.node.keys[gap.index:gap.node.nrSegments])
	copy(gap.node.values[gap.index+1:], gap.node.values[gap.index:gap.node.nrSegments])
	gap.node.keys[gap.index] = r
	gap.node.values[gap.index] = val
	gap.node.nrSegments++
	if splitMaxGap {
		gap.node.updateMaxGapLeaf()
	}
	return Iterator(gap)
}

// InsertRange inserts the given segment into the set. If the new segment can
// be merged with adjacent segments, InsertRange will do so. InsertRange
// returns an iterator to the segment containing the inserted value (which may
// have been merged with other values). All existing iterators (excluding the
// returned iterator) are invalidated.
//
// If the new segment would overlap an existing segment, or if r is invalid,
// InsertRange panics.
//
// InsertRange searches the set to find the gap to insert into. If the caller
// already has the appropriate GapIterator, or if the caller needs to do
// additional work between finding the gap and insertion, use Insert instead.
func (s *Set) InsertRange(r Range, val Value) Iterator {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	seg, gap := s.Find(r.Start)
	if seg.Ok() {
		panic(fmt.Sprintf("new segment %v overlaps existing segment %v", r, seg.Range()))
	}
	if gap.End() < r.End {
		panic(fmt.Sprintf("new segment %v overlaps existing segment %v", r, gap.NextSegment().Range()))
	}
	return s.Insert(gap, r, val)
}

// InsertWithoutMergingRange inserts the given segment into the set and returns
// an iterator to the inserted segment. All existing iterators (excluding the
// returned iterator) are invalidated.
//
// If the new segment would overlap an existing segment, or if r is invalid,
// InsertWithoutMergingRange panics.
//
// InsertWithoutMergingRange searches the set to find the gap to insert into.
// If the caller already has the appropriate GapIterator, or if the caller
// needs to do additional work between finding the gap and insertion, use
// InsertWithoutMerging instead.
func (s *Set) InsertWithoutMergingRange(r Range, val Value) Iterator {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	seg, gap := s.Find(r.Start)
	if seg.Ok() {
		panic(fmt.Sprintf("new segment %v overlaps existing segment %v", r, seg.Range()))
	}
	if gap.End() < r.End {
		panic(fmt.Sprintf("new segment %v overlaps existing segment %v", r, gap.NextSegment().Range()))
	}
	return s.InsertWithoutMerging(gap, r, val)
}

// TryInsertRange attempts to insert the given segment into the set. If the new
// segment can be merged with adjacent segments, TryInsertRange will do so.
// TryInsertRange returns an iterator to the segment containing the inserted
// value (which may have been merged with other values). All existing iterators
// (excluding the returned iterator) are invalidated.
//
// If the new segment would overlap an existing segment, TryInsertRange does
// nothing and returns a terminal iterator.
//
// TryInsertRange searches the set to find the gap to insert into. If the
// caller already has the appropriate GapIterator, or if the caller needs to do
// additional work between finding the gap and insertion, use Insert instead.
func (s *Set) TryInsertRange(r Range, val Value) Iterator {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	seg, gap := s.Find(r.Start)
	if seg.Ok() {
		return Iterator{}
	}
	if gap.End() < r.End {
		return Iterator{}
	}
	return s.Insert(gap, r, val)
}

// TryInsertWithoutMergingRange attempts to insert the given segment into the
// set. If successful, it returns an iterator to the inserted segment; all
// existing iterators (excluding the returned iterator) are invalidated. If the
// new segment would overlap an existing segment, TryInsertWithoutMergingRange
// does nothing and returns a terminal iterator.
//
// TryInsertWithoutMergingRange searches the set to find the gap to insert
// into. If the caller already has the appropriate GapIterator, or if the
// caller needs to do additional work between finding the gap and insertion,
// use InsertWithoutMerging instead.
func (s *Set) TryInsertWithoutMergingRange(r Range, val Value) Iterator {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	seg, gap := s.Find(r.Start)
	if seg.Ok() {
		return Iterator{}
	}
	if gap.End() < r.End {
		return Iterator{}
	}
	return s.InsertWithoutMerging(gap, r, val)
}

// Remove removes the given segment and returns an iterator to the vacated gap.
// All existing iterators (including seg, but not including the returned
// iterator) are invalidated.
func (s *Set) Remove(seg Iterator) GapIterator {
	// We only want to remove directly from a leaf node.
	if seg.node.hasChildren {
		// Since seg.node has children, the removed segment must have a
		// predecessor (at the end of the rightmost leaf of its left child
		// subtree). Move the contents of that predecessor into the removed
		// segment's position, and remove that predecessor instead. (We choose
		// to steal the predecessor rather than the successor because removing
		// from the end of a leaf node doesn't involve any copying unless
		// merging is required.)
		victim := seg.PrevSegment()
		// This must be unchecked since until victim is removed, seg and victim
		// overlap.
		seg.SetRangeUnchecked(victim.Range())
		seg.SetValue(victim.Value())
		// Need to update the nextAdjacentNode's maxGap because the gap in between
		// must have been modified by updating seg.Range() to victim.Range().
		// seg.NextSegment() must exist since the last segment can't be in a
		// non-leaf node.
		nextAdjacentNode := seg.NextSegment().node
		if trackGaps != 0 {
			nextAdjacentNode.updateMaxGapLeaf()
		}
		return s.Remove(victim).NextGap()
	}
	copy(seg.node.keys[seg.index:], seg.node.keys[seg.index+1:seg.node.nrSegments])
	copy(seg.node.values[seg.index:], seg.node.values[seg.index+1:seg.node.nrSegments])
	Functions{}.ClearValue(&seg.node.values[seg.node.nrSegments-1])
	seg.node.nrSegments--
	if trackGaps != 0 {
		seg.node.updateMaxGapLeaf()
	}
	return seg.node.rebalanceAfterRemove(GapIterator(seg))
}

// RemoveAll removes all segments from the set. All existing iterators are
// invalidated.
func (s *Set) RemoveAll() {
	s.root = node{}
}

// RemoveRange removes all segments in the given range. An iterator to the
// newly formed gap is returned, and all existing iterators are invalidated.
//
// RemoveRange searches the set to find segments to remove. If the caller
// already has an iterator to either end of the range of segments to remove, or
// if the caller needs to do additional work before removing each segment,
// iterate segments and call Remove in a loop instead.
func (s *Set) RemoveRange(r Range) GapIterator {
	return s.RemoveRangeWith(r, nil)
}

// RemoveFullRange is equivalent to RemoveRange, except that if any key in the
// given range does not correspond to a segment, RemoveFullRange panics.
func (s *Set) RemoveFullRange(r Range) GapIterator {
	return s.RemoveFullRangeWith(r, nil)
}

// RemoveRangeWith removes all segments in the given range. An iterator to the
// newly formed gap is returned, and all existing iterators are invalidated.
//
// The function f is applied to each segment immediately before it is removed,
// in order of ascending keys. Segments that lie partially outside r are split
// before f is called, such that f only observes segments entirely within r.
// Non-empty gaps between segments are skipped.
//
// RemoveRangeWith searches the set to find segments to remove. If the caller
// already has an iterator to either end of the range of segments to remove, or
// if the caller needs to do additional work before removing each segment,
// iterate segments and call Remove in a loop instead.
//
// N.B. f must not invalidate iterators into s.
func (s *Set) RemoveRangeWith(r Range, f func(seg Iterator)) GapIterator {
	seg, gap := s.Find(r.Start)
	if seg.Ok() {
		seg = s.Isolate(seg, r)
		if f != nil {
			f(seg)
		}
		gap = s.Remove(seg)
	}
	for seg = gap.NextSegment(); seg.Ok() && seg.Start() < r.End; seg = gap.NextSegment() {
		seg = s.SplitAfter(seg, r.End)
		if f != nil {
			f(seg)
		}
		gap = s.Remove(seg)
	}
	return gap
}

// RemoveFullRangeWith is equivalent to RemoveRangeWith, except that if any key
// in the given range does not correspond to a segment, RemoveFullRangeWith
// panics.
func (s *Set) RemoveFullRangeWith(r Range, f func(seg Iterator)) GapIterator {
	seg := s.FindSegment(r.Start)
	if !seg.Ok() {
		panic(fmt.Sprintf("missing segment at %v", r.Start))
	}
	seg = s.SplitBefore(seg, r.Start)
	for {
		seg = s.SplitAfter(seg, r.End)
		if f != nil {
			f(seg)
		}
		end := seg.End()
		gap := s.Remove(seg)
		if r.End <= end {
			return gap
		}
		seg = gap.NextSegment()
		if !seg.Ok() || seg.Start() != end {
			panic(fmt.Sprintf("missing segment at %v", end))
		}
	}
}

// MoveFrom moves all segments from s2 to s, replacing all existing segments in
// s and leaving s2 empty.
func (s *Set) MoveFrom(s2 *Set) {
	*s = *s2
	for _, child := range s.root.children {
		if child == nil {
			break
		}
		child.parent = &s.root
	}
	s2.RemoveAll()
}

// Merge attempts to merge two neighboring segments. If successful, Merge
// returns an iterator to the merged segment, and all existing iterators are
// invalidated. Otherwise, Merge returns a terminal iterator.
//
// If first is not the predecessor of second, Merge panics.
func (s *Set) Merge(first, second Iterator) Iterator {
	if first.NextSegment() != second {
		panic(fmt.Sprintf("attempt to merge non-neighboring segments %v, %v", first.Range(), second.Range()))
	}
	return s.MergeUnchecked(first, second)
}

// MergeUnchecked attempts to merge two neighboring segments. If successful,
// MergeUnchecked returns an iterator to the merged segment, and all existing
// iterators are invalidated. Otherwise, MergeUnchecked returns a terminal
// iterator.
//
// Precondition: first is the predecessor of second: first.NextSegment() ==
// second, first == second.PrevSegment().
func (s *Set) MergeUnchecked(first, second Iterator) Iterator {
	if first.End() == second.Start() {
		if mval, ok := (Functions{}).Merge(first.Range(), first.Value(), second.Range(), second.Value()); ok {
			// N.B. This must be unchecked because until s.Remove(second), first
			// overlaps second.
			first.SetEndUnchecked(second.End())
			first.SetValue(mval)
			// Remove will handle the maxGap update if necessary.
			return s.Remove(second).PrevSegment()
		}
	}
	return Iterator{}
}

// MergePrev attempts to merge the given segment with its predecessor if
// possible, and returns an updated iterator to the extended segment. All
// existing iterators (including seg, but not including the returned iterator)
// are invalidated.
//
// MergePrev is usually used when mutating segments while iterating them in
// order of increasing keys, to attempt merging of each mutated segment with
// its previously-mutated predecessor. In such cases, merging a mutated segment
// with its unmutated successor would incorrectly cause the latter to be
// skipped.
func (s *Set) MergePrev(seg Iterator) Iterator {
	if prev := seg.PrevSegment(); prev.Ok() {
		if mseg := s.MergeUnchecked(prev, seg); mseg.Ok() {
			seg = mseg
		}
	}
	return seg
}

// MergeNext attempts to merge the given segment with its successor if
// possible, and returns an updated iterator to the extended segment. All
// existing iterators (including seg, but not including the returned iterator)
// are invalidated.
//
// MergeNext is usually used when mutating segments while iterating them in
// order of decreasing keys, to attempt merging of each mutated segment with
// its previously-mutated successor. In such cases, merging a mutated segment
// with its unmutated predecessor would incorrectly cause the latter to be
// skipped.
func (s *Set) MergeNext(seg Iterator) Iterator {
	if next := seg.NextSegment(); next.Ok() {
		if mseg := s.MergeUnchecked(seg, next); mseg.Ok() {
			seg = mseg
		}
	}
	return seg
}

// Unisolate attempts to merge the given segment with its predecessor and
// successor if possible, and returns an updated iterator to the extended
// segment. All existing iterators (including seg, but not including the
// returned iterator) are invalidated.
//
// Unisolate is usually used in conjunction with Isolate when mutating part of
// a single segment in a way that may affect its mergeability. For the reasons
// described by MergePrev and MergeNext, it is usually incorrect to use the
// return value of Unisolate in a loop variable.
func (s *Set) Unisolate(seg Iterator) Iterator {
	if prev := seg.PrevSegment(); prev.Ok() {
		if mseg := s.MergeUnchecked(prev, seg); mseg.Ok() {
			seg = mseg
		}
	}
	if next := seg.NextSegment(); next.Ok() {
		if mseg := s.MergeUnchecked(seg, next); mseg.Ok() {
			seg = mseg
		}
	}
	return seg
}

// MergeAll merges all mergeable adjacent segments in the set. All existing
// iterators are invalidated.
func (s *Set) MergeAll() {
	seg := s.FirstSegment()
	if !seg.Ok() {
		return
	}
	next := seg.NextSegment()
	for next.Ok() {
		if mseg := s.MergeUnchecked(seg, next); mseg.Ok() {
			seg, next = mseg, mseg.NextSegment()
		} else {
			seg, next = next, next.NextSegment()
		}
	}
}

// MergeInsideRange attempts to merge all adjacent segments that contain a key
// in the specific range. All existing iterators are invalidated.
//
// MergeInsideRange only makes sense after mutating the set in a way that may
// change the mergeability of modified segments; callers should prefer to use
// MergePrev or MergeNext during the mutating loop instead (depending on the
// direction of iteration), in order to avoid a redundant search.
func (s *Set) MergeInsideRange(r Range) {
	seg := s.LowerBoundSegment(r.Start)
	if !seg.Ok() {
		return
	}
	next := seg.NextSegment()
	for next.Ok() && next.Start() < r.End {
		if mseg := s.MergeUnchecked(seg, next); mseg.Ok() {
			seg, next = mseg, mseg.NextSegment()
		} else {
			seg, next = next, next.NextSegment()
		}
	}
}

// MergeOutsideRange attempts to merge the segment containing r.Start with its
// predecessor, and the segment containing r.End-1 with its successor.
//
// MergeOutsideRange only makes sense after mutating the set in a way that may
// change the mergeability of modified segments; callers should prefer to use
// MergePrev or MergeNext during the mutating loop instead (depending on the
// direction of iteration), in order to avoid two redundant searches.
func (s *Set) MergeOutsideRange(r Range) {
	first := s.FindSegment(r.Start)
	if first.Ok() {
		if prev := first.PrevSegment(); prev.Ok() {
			s.Merge(prev, first)
		}
	}
	last := s.FindSegment(r.End - 1)
	if last.Ok() {
		if next := last.NextSegment(); next.Ok() {
			s.Merge(last, next)
		}
	}
}

// Split splits the given segment at the given key and returns iterators to the
// two resulting segments. All existing iterators (including seg, but not
// including the returned iterators) are invalidated.
//
// If the segment cannot be split at split (because split is at the start or
// end of the segment's range, so splitting would produce a segment with zero
// length, or because split falls outside the segment's range altogether),
// Split panics.
func (s *Set) Split(seg Iterator, split Key) (Iterator, Iterator) {
	if !seg.Range().CanSplitAt(split) {
		panic(fmt.Sprintf("can't split %v at %v", seg.Range(), split))
	}
	return s.SplitUnchecked(seg, split)
}

// SplitUnchecked splits the given segment at the given key and returns
// iterators to the two resulting segments. All existing iterators (including
// seg, but not including the returned iterators) are invalidated.
//
// Preconditions: seg.Start() < key < seg.End().
func (s *Set) SplitUnchecked(seg Iterator, split Key) (Iterator, Iterator) {
	val1, val2 := (Functions{}).Split(seg.Range(), seg.Value(), split)
	end2 := seg.End()
	seg.SetEndUnchecked(split)
	seg.SetValue(val1)
	seg2 := s.InsertWithoutMergingUnchecked(seg.NextGap(), Range{split, end2}, val2)
	// seg may now be invalid due to the Insert.
	return seg2.PrevSegment(), seg2
}

// SplitBefore ensures that the given segment's start is at least start by
// splitting at start if necessary, and returns an updated iterator to the
// bounded segment. All existing iterators (including seg, but not including
// the returned iterator) are invalidated.
//
// SplitBefore is usually when mutating segments in a range. In such cases,
// when iterating segments in order of increasing keys, the first segment may
// extend beyond the start of the range to be mutated, and needs to be
// SplitBefore to ensure that only the part of the segment within the range is
// mutated. When iterating segments in order of decreasing keys, SplitBefore
// and SplitAfter; i.e. SplitBefore needs to be invoked on each segment, while
// SplitAfter only needs to be invoked on the first.
//
// Preconditions: start < seg.End().
func (s *Set) SplitBefore(seg Iterator, start Key) Iterator {
	if seg.Range().CanSplitAt(start) {
		_, seg = s.SplitUnchecked(seg, start)
	}
	return seg
}

// SplitAfter ensures that the given segment's end is at most end by splitting
// at end if necessary, and returns an updated iterator to the bounded segment.
// All existing iterators (including seg, but not including the returned
// iterator) are invalidated.
//
// SplitAfter is usually used when mutating segments in a range. In such cases,
// when iterating segments in order of increasing keys, each iterated segment
// may extend beyond the end of the range to be mutated, and needs to be
// SplitAfter to ensure that only the part of the segment within the range is
// mutated. When iterating segments in order of decreasing keys, SplitBefore
// and SplitAfter exchange roles; i.e. SplitBefore needs to be invoked on each
// segment, while SplitAfter only needs to be invoked on the first.
//
// Preconditions: seg.Start() < end.
func (s *Set) SplitAfter(seg Iterator, end Key) Iterator {
	if seg.Range().CanSplitAt(end) {
		seg, _ = s.SplitUnchecked(seg, end)
	}
	return seg
}

// Isolate ensures that the given segment's range is a subset of r by splitting
// at r.Start and r.End if necessary, and returns an updated iterator to the
// bounded segment. All existing iterators (including seg, but not including
// the returned iterators) are invalidated.
//
// Isolate is usually used when mutating part of a single segment, or when
// mutating segments in a range where the first segment is not necessarily
// split, making use of SplitBefore/SplitAfter complex.
//
// Preconditions: seg.Range().Overlaps(r).
func (s *Set) Isolate(seg Iterator, r Range) Iterator {
	if seg.Range().CanSplitAt(r.Start) {
		_, seg = s.SplitUnchecked(seg, r.Start)
	}
	if seg.Range().CanSplitAt(r.End) {
		seg, _ = s.SplitUnchecked(seg, r.End)
	}
	return seg
}

// LowerBoundSegmentSplitBefore combines LowerBoundSegment and SplitBefore.
//
// LowerBoundSegmentSplitBefore is usually used when mutating segments in a
// range while iterating them in order of increasing keys. In such cases,
// LowerBoundSegmentSplitBefore provides an iterator to the first segment to be
// mutated, suitable as the initial value for a loop variable.
func (s *Set) LowerBoundSegmentSplitBefore(min Key) Iterator {
	seg, gap := s.Find(min)
	if seg.Ok() {
		return s.SplitBefore(seg, min)
	}
	return gap.NextSegment()
}

// UpperBoundSegmentSplitAfter combines UpperBoundSegment and SplitAfter.
//
// UpperBoundSegmentSplitAfter is usually used when mutating segments in a
// range while iterating them in order of decreasing keys. In such cases,
// UpperBoundSegmentSplitAfter provides an iterator to the first segment to be
// mutated, suitable as the initial value for a loop variable.
func (s *Set) UpperBoundSegmentSplitAfter(max Key) Iterator {
	seg, gap := s.Find(max)
	if seg.Ok() {
		return s.SplitAfter(seg, max)
	}
	return gap.PrevSegment()
}

// VisitRange applies the function f to all segments intersecting the range r,
// in order of ascending keys. Segments will not be split, so f may be called
// on segments lying partially outside r. Non-empty gaps between segments are
// skipped. If a call to f returns false, VisitRange stops iteration
// immediately.
//
// N.B. f must not invalidate iterators into s.
func (s *Set) VisitRange(r Range, f func(seg Iterator) bool) {
	for seg := s.LowerBoundSegment(r.Start); seg.Ok() && seg.Start() < r.End; seg = seg.NextSegment() {
		if !f(seg) {
			return
		}
	}
}

// VisitFullRange is equivalent to VisitRange, except that if any key in r that
// is visited before f returns false does not correspond to a segment,
// VisitFullRange panics.
func (s *Set) VisitFullRange(r Range, f func(seg Iterator) bool) {
	pos := r.Start
	seg := s.FindSegment(r.Start)
	for {
		if !seg.Ok() {
			panic(fmt.Sprintf("missing segment at %v", pos))
		}
		if !f(seg) {
			return
		}
		pos = seg.End()
		if r.End <= pos {
			return
		}
		seg, _ = seg.NextNonEmpty()
	}
}

// MutateRange applies the function f to all segments intersecting the range r,
// in order of ascending keys. Segments that lie partially outside r are split
// before f is called, such that f only observes segments entirely within r.
// Iterated segments are merged again after f is called. Non-empty gaps between
// segments are skipped. If a call to f returns false, MutateRange stops
// iteration immediately.
//
// MutateRange invalidates all existing iterators.
//
// N.B. f must not invalidate iterators into s.
func (s *Set) MutateRange(r Range, f func(seg Iterator) bool) {
	seg := s.LowerBoundSegmentSplitBefore(r.Start)
	for seg.Ok() && seg.Start() < r.End {
		seg = s.SplitAfter(seg, r.End)
		cont := f(seg)
		seg = s.MergePrev(seg)
		if !cont {
			s.MergeNext(seg)
			return
		}
		seg = seg.NextSegment()
	}
	if seg.Ok() {
		s.MergePrev(seg)
	}
}

// MutateFullRange is equivalent to MutateRange, except that if any key in r
// that is visited before f returns false does not correspond to a segment,
// MutateFullRange panics.
func (s *Set) MutateFullRange(r Range, f func(seg Iterator) bool) {
	seg := s.FindSegment(r.Start)
	if !seg.Ok() {
		panic(fmt.Sprintf("missing segment at %v", r.Start))
	}
	seg = s.SplitBefore(seg, r.Start)
	for {
		seg = s.SplitAfter(seg, r.End)
		cont := f(seg)
		end := seg.End()
		seg = s.MergePrev(seg)
		if !cont || r.End <= end {
			s.MergeNext(seg)
			return
		}
		seg = seg.NextSegment()
		if !seg.Ok() || seg.Start() != end {
			panic(fmt.Sprintf("missing segment at %v", end))
		}
	}
}

// +stateify savable
type node struct {
	// An internal binary tree node looks like:
	//
	//   K
	//  / \
	// Cl Cr
	//
	// where all keys in the subtree rooted by Cl (the left subtree) are less
	// than K (the key of the parent node), and all keys in the subtree rooted
	// by Cr (the right subtree) are greater than K.
	//
	// An internal B-tree node's indexes work out to look like:
	//
	//   K0 K1 K2  ...   Kn-1
	//  / \/ \/ \  ...  /  \
	// C0 C1 C2 C3 ... Cn-1 Cn
	//
	// where n is nrSegments.
	nrSegments int

	// parent is a pointer to this node's parent. If this node is root, parent
	// is nil.
	parent *node

	// parentIndex is the index of this node in parent.children.
	parentIndex int

	// Flag for internal nodes that is technically redundant with "children[0]
	// != nil", but is stored in the first cache line. "hasChildren" rather
	// than "isLeaf" because false must be the correct value for an empty root.
	hasChildren bool

	// The longest gap within this node. If the node is a leaf, it's simply the
	// maximum gap among all the (nrSegments+1) gaps formed by its nrSegments keys
	// including the 0th and nrSegments-th gap possibly shared with its upper-level
	// nodes; if it's a non-leaf node, it's the max of all children's maxGap.
	maxGap dynamicGap

	// Nodes store keys and values in separate arrays to maximize locality in
	// the common case (scanning keys for lookup).
	keys     [maxDegree - 1]Range
	values   [maxDegree - 1]Value
	children [maxDegree]*node
}

// firstSegment returns the first segment in the subtree rooted by n.
//
// Preconditions: n.nrSegments != 0.
func (n *node) firstSegment() Iterator {
	for n.hasChildren {
		n = n.children[0]
	}
	return Iterator{n, 0}
}

// lastSegment returns the last segment in the subtree rooted by n.
//
// Preconditions: n.nrSegments != 0.
func (n *node) lastSegment() Iterator {
	for n.hasChildren {
		n = n.children[n.nrSegments]
	}
	return Iterator{n, n.nrSegments - 1}
}

func (n *node) prevSibling() *node {
	if n.parent == nil || n.parentIndex == 0 {
		return nil
	}
	return n.parent.children[n.parentIndex-1]
}

func (n *node) nextSibling() *node {
	if n.parent == nil || n.parentIndex == n.parent.nrSegments {
		return nil
	}
	return n.parent.children[n.parentIndex+1]
}

// rebalanceBeforeInsert splits n and its ancestors if they are full, as
// required for insertion, and returns an updated iterator to the position
// represented by gap.
func (n *node) rebalanceBeforeInsert(gap GapIterator) GapIterator {
	if n.nrSegments < maxDegree-1 {
		return gap
	}
	if n.parent != nil {
		gap = n.parent.rebalanceBeforeInsert(gap)
	}
	if n.parent == nil {
		// n is root. Move all segments before and after n's median segment
		// into new child nodes adjacent to the median segment, which is now
		// the only segment in root.
		left := &node{
			nrSegments:  minDegree - 1,
			parent:      n,
			parentIndex: 0,
			hasChildren: n.hasChildren,
		}
		right := &node{
			nrSegments:  minDegree - 1,
			parent:      n,
			parentIndex: 1,
			hasChildren: n.hasChildren,
		}
		copy(left.keys[:minDegree-1], n.keys[:minDegree-1])
		copy(left.values[:minDegree-1], n.values[:minDegree-1])
		copy(right.keys[:minDegree-1], n.keys[minDegree:])
		copy(right.values[:minDegree-1], n.values[minDegree:])
		n.keys[0], n.values[0] = n.keys[minDegree-1], n.values[minDegree-1]
		zeroValueSlice(n.values[1:])
		if n.hasChildren {
			copy(left.children[:minDegree], n.children[:minDegree])
			copy(right.children[:minDegree], n.children[minDegree:])
			zeroNodeSlice(n.children[2:])
			for i := 0; i < minDegree; i++ {
				left.children[i].parent = left
				left.children[i].parentIndex = i
				right.children[i].parent = right
				right.children[i].parentIndex = i
			}
		}
		n.nrSegments = 1
		n.hasChildren = true
		n.children[0] = left
		n.children[1] = right
		// In this case, n's maxGap won't violated as it's still the root,
		// but the left and right children should be updated locally as they
		// are newly split from n.
		if trackGaps != 0 {
			left.updateMaxGapLocal()
			right.updateMaxGapLocal()
		}
		if gap.node != n {
			return gap
		}
		if gap.index < minDegree {
			return GapIterator{left, gap.index}
		}
		return GapIterator{right, gap.index - minDegree}
	}
	// n is non-root. Move n's median segment into its parent node (which can't
	// be full because we've already invoked n.parent.rebalanceBeforeInsert)
	// and move all segments after n's median into a new sibling node (the
	// median segment's right child subtree).
	copy(n.parent.keys[n.parentIndex+1:], n.parent.keys[n.parentIndex:n.parent.nrSegments])
	copy(n.parent.values[n.parentIndex+1:], n.parent.values[n.parentIndex:n.parent.nrSegments])
	n.parent.keys[n.parentIndex], n.parent.values[n.parentIndex] = n.keys[minDegree-1], n.values[minDegree-1]
	copy(n.parent.children[n.parentIndex+2:], n.parent.children[n.parentIndex+1:n.parent.nrSegments+1])
	for i := n.parentIndex + 2; i < n.parent.nrSegments+2; i++ {
		n.parent.children[i].parentIndex = i
	}
	sibling := &node{
		nrSegments:  minDegree - 1,
		parent:      n.parent,
		parentIndex: n.parentIndex + 1,
		hasChildren: n.hasChildren,
	}
	n.parent.children[n.parentIndex+1] = sibling
	n.parent.nrSegments++
	copy(sibling.keys[:minDegree-1], n.keys[minDegree:])
	copy(sibling.values[:minDegree-1], n.values[minDegree:])
	zeroValueSlice(n.values[minDegree-1:])
	if n.hasChildren {
		copy(sibling.children[:minDegree], n.children[minDegree:])
		zeroNodeSlice(n.children[minDegree:])
		for i := 0; i < minDegree; i++ {
			sibling.children[i].parent = sibling
			sibling.children[i].parentIndex = i
		}
	}
	n.nrSegments = minDegree - 1
	// MaxGap of n's parent is not violated because the segments within is not changed.
	// n and its sibling's maxGap need to be updated locally as they are two new nodes split from old n.
	if trackGaps != 0 {
		n.updateMaxGapLocal()
		sibling.updateMaxGapLocal()
	}
	// gap.node can't be n.parent because gaps are always in leaf nodes.
	if gap.node != n {
		return gap
	}
	if gap.index < minDegree {
		return gap
	}
	return GapIterator{sibling, gap.index - minDegree}
}

// rebalanceAfterRemove "unsplits" n and its ancestors if they are deficient
// (contain fewer segments than required by B-tree invariants), as required for
// removal, and returns an updated iterator to the position represented by gap.
//
// Precondition: n is the only node in the tree that may currently violate a
// B-tree invariant.
func (n *node) rebalanceAfterRemove(gap GapIterator) GapIterator {
	for {
		if n.nrSegments >= minDegree-1 {
			return gap
		}
		if n.parent == nil {
			// Root is allowed to be deficient.
			return gap
		}
		// There's one other thing we can do before resorting to unsplitting.
		// If either sibling node has at least minDegree segments, rotate that
		// sibling's closest segment through the segment in the parent that
		// separates us. That is, given:
		//
		//      ... D ...
		//         / \
		// ... B C]   [E ...
		//
		// where the node containing E is deficient, end up with:
		//
		//    ... C ...
		//       / \
		// ... B]   [D E ...
		//
		// As in Set.Remove, prefer rotating from the end of the sibling to the
		// left: by precondition, n.node has fewer segments (to memcpy) than
		// the sibling does.
		if sibling := n.prevSibling(); sibling != nil && sibling.nrSegments >= minDegree {
			copy(n.keys[1:], n.keys[:n.nrSegments])
			copy(n.values[1:], n.values[:n.nrSegments])
			n.keys[0] = n.parent.keys[n.parentIndex-1]
			n.values[0] = n.parent.values[n.parentIndex-1]
			n.parent.keys[n.parentIndex-1] = sibling.keys[sibling.nrSegments-1]
			n.parent.values[n.parentIndex-1] = sibling.values[sibling.nrSegments-1]
			Functions{}.ClearValue(&sibling.values[sibling.nrSegments-1])
			if n.hasChildren {
				copy(n.children[1:], n.children[:n.nrSegments+1])
				n.children[0] = sibling.children[sibling.nrSegments]
				sibling.children[sibling.nrSegments] = nil
				n.children[0].parent = n
				n.children[0].parentIndex = 0
				for i := 1; i < n.nrSegments+2; i++ {
					n.children[i].parentIndex = i
				}
			}
			n.nrSegments++
			sibling.nrSegments--
			// n's parent's maxGap does not need to be updated as its content is unmodified.
			// n and its sibling must be updated with (new) maxGap because of the shift of keys.
			if trackGaps != 0 {
				n.updateMaxGapLocal()
				sibling.updateMaxGapLocal()
			}
			if gap.node == sibling && gap.index == sibling.nrSegments {
				return GapIterator{n, 0}
			}
			if gap.node == n {
				return GapIterator{n, gap.index + 1}
			}
			return gap
		}
		if sibling := n.nextSibling(); sibling != nil && sibling.nrSegments >= minDegree {
			n.keys[n.nrSegments] = n.parent.keys[n.parentIndex]
			n.values[n.nrSegments] = n.parent.values[n.parentIndex]
			n.parent.keys[n.parentIndex] = sibling.keys[0]
			n.parent.values[n.parentIndex] = sibling.values[0]
			copy(sibling.keys[:sibling.nrSegments-1], sibling.keys[1:])
			copy(sibling.values[:sibling.nrSegments-1], sibling.values[1:])
			Functions{}.ClearValue(&sibling.values[sibling.nrSegments-1])
			if n.hasChildren {
				n.children[n.nrSegments+1] = sibling.children[0]
				copy(sibling.children[:sibling.nrSegments], sibling.children[1:])
				sibling.children[sibling.nrSegments] = nil
				n.children[n.nrSegments+1].parent = n
				n.children[n.nrSegments+1].parentIndex = n.nrSegments + 1
				for i := 0; i < sibling.nrSegments; i++ {
					sibling.children[i].parentIndex = i
				}
			}
			n.nrSegments++
			sibling.nrSegments--
			// n's parent's maxGap does not need to be updated as its content is unmodified.
			// n and its sibling must be updated with (new) maxGap because of the shift of keys.
			if trackGaps != 0 {
				n.updateMaxGapLocal()
				sibling.updateMaxGapLocal()
			}
			if gap.node == sibling {
				if gap.index == 0 {
					return GapIterator{n, n.nrSegments}
				}
				return GapIterator{sibling, gap.index - 1}
			}
			return gap
		}
		// Otherwise, we must unsplit.
		p := n.parent
		if p.nrSegments == 1 {
			// Merge all segments in both n and its sibling back into n.parent.
			// This is the reverse of the root splitting case in
			// node.rebalanceBeforeInsert. (Because we require minDegree >= 3,
			// only root can have 1 segment in this path, so this reduces the
			// height of the tree by 1, without violating the constraint that
			// all leaf nodes remain at the same depth.)
			left, right := p.children[0], p.children[1]
			p.nrSegments = left.nrSegments + right.nrSegments + 1
			p.hasChildren = left.hasChildren
			p.keys[left.nrSegments] = p.keys[0]
			p.values[left.nrSegments] = p.values[0]
			copy(p.keys[:left.nrSegments], left.keys[:left.nrSegments])
			copy(p.values[:left.nrSegments], left.values[:left.nrSegments])
			copy(p.keys[left.nrSegments+1:], right.keys[:right.nrSegments])
			copy(p.values[left.nrSegments+1:], right.values[:right.nrSegments])
			if left.hasChildren {
				copy(p.children[:left.nrSegments+1], left.children[:left.nrSegments+1])
				copy(p.children[left.nrSegments+1:], right.children[:right.nrSegments+1])
				for i := 0; i < p.nrSegments+1; i++ {
					p.children[i].parent = p
					p.children[i].parentIndex = i
				}
			} else {
				p.children[0] = nil
				p.children[1] = nil
			}
			// No need to update maxGap of p as its content is not changed.
			if gap.node == left {
				return GapIterator{p, gap.index}
			}
			if gap.node == right {
				return GapIterator{p, gap.index + left.nrSegments + 1}
			}
			return gap
		}
		// Merge n and either sibling, along with the segment separating the
		// two, into whichever of the two nodes comes first. This is the
		// reverse of the non-root splitting case in
		// node.rebalanceBeforeInsert.
		var left, right *node
		if n.parentIndex > 0 {
			left = n.prevSibling()
			right = n
		} else {
			left = n
			right = n.nextSibling()
		}
		// Fix up gap first since we need the old left.nrSegments, which
		// merging will change.
		if gap.node == right {
			gap = GapIterator{left, gap.index + left.nrSegments + 1}
		}
		left.keys[left.nrSegments] = p.keys[left.parentIndex]
		left.values[left.nrSegments] = p.values[left.parentIndex]
		copy(left.keys[left.nrSegments+1:], right.keys[:right.nrSegments])
		copy(left.values[left.nrSegments+1:], right.values[:right.nrSegments])
		if left.hasChildren {
			copy(left.children[left.nrSegments+1:], right.children[:right.nrSegments+1])
			for i := left.nrSegments + 1; i < left.nrSegments+right.nrSegments+2; i++ {
				left.children[i].parent = left
				left.children[i].parentIndex = i
			}
		}
		left.nrSegments += right.nrSegments + 1
		copy(p.keys[left.parentIndex:], p.keys[left.parentIndex+1:p.nrSegments])
		copy(p.values[left.parentIndex:], p.values[left.parentIndex+1:p.nrSegments])
		Functions{}.ClearValue(&p.values[p.nrSegments-1])
		copy(p.children[left.parentIndex+1:], p.children[left.parentIndex+2:p.nrSegments+1])
		for i := 0; i < p.nrSegments; i++ {
			p.children[i].parentIndex = i
		}
		p.children[p.nrSegments] = nil
		p.nrSegments--
		// Update maxGap of left locally, no need to change p and right because
		// p's contents is not changed and right is already invalid.
		if trackGaps != 0 {
			left.updateMaxGapLocal()
		}
		// This process robs p of one segment, so recurse into rebalancing p.
		n = p
	}
}

// updateMaxGapLeaf updates maxGap bottom-up from the calling leaf until no
// necessary update.
//
// Preconditions: n must be a leaf node, trackGaps must be 1.
func (n *node) updateMaxGapLeaf() {
	if n.hasChildren {
		panic(fmt.Sprintf("updateMaxGapLeaf should always be called on leaf node: %v", n))
	}
	max := n.calculateMaxGapLeaf()
	if max == n.maxGap.Get() {
		// If new max equals the old maxGap, no update is needed.
		return
	}
	oldMax := n.maxGap.Get()
	n.maxGap.Set(max)
	if max > oldMax {
		// Grow ancestor maxGaps.
		for p := n.parent; p != nil; p = p.parent {
			if p.maxGap.Get() >= max {
				// p and its ancestors already contain an equal or larger gap.
				break
			}
			// Only if new maxGap is larger than parent's
			// old maxGap, propagate this update to parent.
			p.maxGap.Set(max)
		}
		return
	}
	// Shrink ancestor maxGaps.
	for p := n.parent; p != nil; p = p.parent {
		if p.maxGap.Get() > oldMax {
			// p and its ancestors still contain a larger gap.
			break
		}
		// If new max is smaller than the old maxGap, and this gap used
		// to be the maxGap of its parent, iterate parent's children
		// and calculate parent's new maxGap.(It's probable that parent
		// has two children with the old maxGap, but we need to check it anyway.)
		parentNewMax := p.calculateMaxGapInternal()
		if p.maxGap.Get() == parentNewMax {
			// p and its ancestors still contain a gap of at least equal size.
			break
		}
		// If p's new maxGap differs from the old one, propagate this update.
		p.maxGap.Set(parentNewMax)
	}
}

// updateMaxGapLocal updates maxGap of the calling node solely with no
// propagation to ancestor nodes.
//
// Precondition: trackGaps must be 1.
func (n *node) updateMaxGapLocal() {
	if !n.hasChildren {
		// Leaf node iterates its gaps.
		n.maxGap.Set(n.calculateMaxGapLeaf())
	} else {
		// Non-leaf node iterates its children.
		n.maxGap.Set(n.calculateMaxGapInternal())
	}
}

// calculateMaxGapLeaf iterates the gaps within a leaf node and calculate the
// max.
//
// Preconditions: n must be a leaf node.
func (n *node) calculateMaxGapLeaf() Key {
	max := GapIterator{n, 0}.Range().Length()
	for i := 1; i <= n.nrSegments; i++ {
		if current := (GapIterator{n, i}).Range().Length(); current > max {
			max = current
		}
	}
	return max
}

// calculateMaxGapInternal iterates children's maxGap within an internal node n
// and calculate the max.
//
// Preconditions: n must be a non-leaf node.
func (n *node) calculateMaxGapInternal() Key {
	max := n.children[0].maxGap.Get()
	for i := 1; i <= n.nrSegments; i++ {
		if current := n.children[i].maxGap.Get(); current > max {
			max = current
		}
	}
	return max
}

// searchFirstLargeEnoughGap returns the first gap having at least minSize length
// in the subtree rooted by n. If not found, return a terminal gap iterator.
func (n *node) searchFirstLargeEnoughGap(minSize Key) GapIterator {
	if n.maxGap.Get() < minSize {
		return GapIterator{}
	}
	if n.hasChildren {
		for i := 0; i <= n.nrSegments; i++ {
			if largeEnoughGap := n.children[i].searchFirstLargeEnoughGap(minSize); largeEnoughGap.Ok() {
				return largeEnoughGap
			}
		}
	} else {
		for i := 0; i <= n.nrSegments; i++ {
			currentGap := GapIterator{n, i}
			if currentGap.Range().Length() >= minSize {
				return currentGap
			}
		}
	}
	panic(fmt.Sprintf("invalid maxGap in %v", n))
}

// searchLastLargeEnoughGap returns the last gap having at least minSize length
// in the subtree rooted by n. If not found, return a terminal gap iterator.
func (n *node) searchLastLargeEnoughGap(minSize Key) GapIterator {
	if n.maxGap.Get() < minSize {
		return GapIterator{}
	}
	if n.hasChildren {
		for i := n.nrSegments; i >= 0; i-- {
			if largeEnoughGap := n.children[i].searchLastLargeEnoughGap(minSize); largeEnoughGap.Ok() {
				return largeEnoughGap
			}
		}
	} else {
		for i := n.nrSegments; i >= 0; i-- {
			currentGap := GapIterator{n, i}
			if currentGap.Range().Length() >= minSize {
				return currentGap
			}
		}
	}
	panic(fmt.Sprintf("invalid maxGap in %v", n))
}

// A Iterator is conceptually one of:
//
//   - A pointer to a segment in a set; or
//
//   - A terminal iterator, which is a sentinel indicating that the end of
//     iteration has been reached.
//
// Iterators are copyable values and are meaningfully equality-comparable. The
// zero value of Iterator is a terminal iterator.
//
// Unless otherwise specified, any mutation of a set invalidates all existing
// iterators into the set.
type Iterator struct {
	// node is the node containing the iterated segment. If the iterator is
	// terminal, node is nil.
	node *node

	// index is the index of the segment in node.keys/values.
	index int
}

// Ok returns true if the iterator is not terminal. All other methods are only
// valid for non-terminal iterators.
func (seg Iterator) Ok() bool {
	return seg.node != nil
}

// Range returns the iterated segment's range key.
func (seg Iterator) Range() Range {
	return seg.node.keys[seg.index]
}

// Start is equivalent to Range().Start, but should be preferred if only the
// start of the range is needed.
func (seg Iterator) Start() Key {
	return seg.node.keys[seg.index].Start
}

// End is equivalent to Range().End, but should be preferred if only the end of
// the range is needed.
func (seg Iterator) End() Key {
	return seg.node.keys[seg.index].End
}

// SetRangeUnchecked mutates the iterated segment's range key. This operation
// does not invalidate any iterators.
//
// Preconditions:
// - r.Length() > 0.
// - The new range must not overlap an existing one:
//   - If seg.NextSegment().Ok(), then r.end <= seg.NextSegment().Start().
//   - If seg.PrevSegment().Ok(), then r.start >= seg.PrevSegment().End().
func (seg Iterator) SetRangeUnchecked(r Range) {
	seg.node.keys[seg.index] = r
}

// SetRange mutates the iterated segment's range key. If the new range would
// cause the iterated segment to overlap another segment, or if the new range
// is invalid, SetRange panics. This operation does not invalidate any
// iterators.
func (seg Iterator) SetRange(r Range) {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	if prev := seg.PrevSegment(); prev.Ok() && r.Start < prev.End() {
		panic(fmt.Sprintf("new segment range %v overlaps segment range %v", r, prev.Range()))
	}
	if next := seg.NextSegment(); next.Ok() && r.End > next.Start() {
		panic(fmt.Sprintf("new segment range %v overlaps segment range %v", r, next.Range()))
	}
	seg.SetRangeUnchecked(r)
}

// SetStartUnchecked mutates the iterated segment's start. This operation does
// not invalidate any iterators.
//
// Preconditions: The new start must be valid:
//   - start < seg.End()
//   - If seg.PrevSegment().Ok(), then start >= seg.PrevSegment().End().
func (seg Iterator) SetStartUnchecked(start Key) {
	seg.node.keys[seg.index].Start = start
}

// SetStart mutates the iterated segment's start. If the new start value would
// cause the iterated segment to overlap another segment, or would result in an
// invalid range, SetStart panics. This operation does not invalidate any
// iterators.
func (seg Iterator) SetStart(start Key) {
	if start >= seg.End() {
		panic(fmt.Sprintf("new start %v would invalidate segment range %v", start, seg.Range()))
	}
	if prev := seg.PrevSegment(); prev.Ok() && start < prev.End() {
		panic(fmt.Sprintf("new start %v would cause segment range %v to overlap segment range %v", start, seg.Range(), prev.Range()))
	}
	seg.SetStartUnchecked(start)
}

// SetEndUnchecked mutates the iterated segment's end. This operation does not
// invalidate any iterators.
//
// Preconditions: The new end must be valid:
//   - end > seg.Start().
//   - If seg.NextSegment().Ok(), then end <= seg.NextSegment().Start().
func (seg Iterator) SetEndUnchecked(end Key) {
	seg.node.keys[seg.index].End = end
}

// SetEnd mutates the iterated segment's end. If the new end value would cause
// the iterated segment to overlap another segment, or would result in an
// invalid range, SetEnd panics. This operation does not invalidate any
// iterators.
func (seg Iterator) SetEnd(end Key) {
	if end <= seg.Start() {
		panic(fmt.Sprintf("new end %v would invalidate segment range %v", end, seg.Range()))
	}
	if next := seg.NextSegment(); next.Ok() && end > next.Start() {
		panic(fmt.Sprintf("new end %v would cause segment range %v to overlap segment range %v", end, seg.Range(), next.Range()))
	}
	seg.SetEndUnchecked(end)
}

// Value returns a copy of the iterated segment's value.
func (seg Iterator) Value() Value {
	return seg.node.values[seg.index]
}

// ValuePtr returns a pointer to the iterated segment's value. The pointer is
// invalidated if the iterator is invalidated. This operation does not
// invalidate any iterators.
func (seg Iterator) ValuePtr() *Value {
	return &seg.node.values[seg.index]
}

// SetValue mutates the iterated segment's value. This operation does not
// invalidate any iterators.
func (seg Iterator) SetValue(val Value) {
	seg.node.values[seg.index] = val
}

// PrevSegment returns the iterated segment's predecessor. If there is no
// preceding segment, PrevSegment returns a terminal iterator.
func (seg Iterator) PrevSegment() Iterator {
	if seg.node.hasChildren {
		return seg.node.children[seg.index].lastSegment()
	}
	if seg.index > 0 {
		return Iterator{seg.node, seg.index - 1}
	}
	if seg.node.parent == nil {
		return Iterator{}
	}
	return segmentBeforePosition(seg.node.parent, seg.node.parentIndex)
}

// NextSegment returns the iterated segment's successor. If there is no
// succeeding segment, NextSegment returns a terminal iterator.
func (seg Iterator) NextSegment() Iterator {
	if seg.node.hasChildren {
		return seg.node.children[seg.index+1].firstSegment()
	}
	if seg.index < seg.node.nrSegments-1 {
		return Iterator{seg.node, seg.index + 1}
	}
	if seg.node.parent == nil {
		return Iterator{}
	}
	return segmentAfterPosition(seg.node.parent, seg.node.parentIndex)
}

// PrevGap returns the gap immediately before the iterated segment.
func (seg Iterator) PrevGap() GapIterator {
	if seg.node.hasChildren {
		// Note that this isn't recursive because the last segment in a subtree
		// must be in a leaf node.
		return seg.node.children[seg.index].lastSegment().NextGap()
	}
	return GapIterator(seg)
}

// NextGap returns the gap immediately after the iterated segment.
func (seg Iterator) NextGap() GapIterator {
	if seg.node.hasChildren {
		return seg.node.children[seg.index+1].firstSegment().PrevGap()
	}
	return GapIterator{seg.node, seg.index + 1}
}

// PrevNonEmpty returns the iterated segment's predecessor if it is adjacent,
// or the gap before the iterated segment otherwise. If seg.Start() ==
// Functions.MinKey(), PrevNonEmpty will return two terminal iterators.
// Otherwise, exactly one of the iterators returned by PrevNonEmpty will be
// non-terminal.
func (seg Iterator) PrevNonEmpty() (Iterator, GapIterator) {
	if prev := seg.PrevSegment(); prev.Ok() && prev.End() == seg.Start() {
		return prev, GapIterator{}
	}
	return Iterator{}, seg.PrevGap()
}

// NextNonEmpty returns the iterated segment's successor if it is adjacent, or
// the gap after the iterated segment otherwise. If seg.End() ==
// Functions.MaxKey(), NextNonEmpty will return two terminal iterators.
// Otherwise, exactly one of the iterators returned by NextNonEmpty will be
// non-terminal.
func (seg Iterator) NextNonEmpty() (Iterator, GapIterator) {
	if next := seg.NextSegment(); next.Ok() && next.Start() == seg.End() {
		return next, GapIterator{}
	}
	return Iterator{}, seg.NextGap()
}

// A GapIterator is conceptually one of:
//
//   - A pointer to a position between two segments, before the first segment, or
//     after the last segment in a set, called a *gap*; or
//
//   - A terminal iterator, which is a sentinel indicating that the end of
//     iteration has been reached.
//
// Note that the gap between two adjacent segments exists (iterators to it are
// non-terminal), but has a length of zero. GapIterator.IsEmpty returns true
// for such gaps. An empty set contains a single gap, spanning the entire range
// of the set's keys.
//
// GapIterators are copyable values and are meaningfully equality-comparable.
// The zero value of GapIterator is a terminal iterator.
//
// Unless otherwise specified, any mutation of a set invalidates all existing
// iterators into the set.
type GapIterator struct {
	// The representation of a GapIterator is identical to that of an Iterator,
	// except that index corresponds to positions between segments in the same
	// way as for node.children (see comment for node.nrSegments).
	node  *node
	index int
}

// Ok returns true if the iterator is not terminal. All other methods are only
// valid for non-terminal iterators.
func (gap GapIterator) Ok() bool {
	return gap.node != nil
}

// Range returns the range spanned by the iterated gap.
func (gap GapIterator) Range() Range {
	return Range{gap.Start(), gap.End()}
}

// Start is equivalent to Range().Start, but should be preferred if only the
// start of the range is needed.
func (gap GapIterator) Start() Key {
	if ps := gap.PrevSegment(); ps.Ok() {
		return ps.End()
	}
	return Functions{}.MinKey()
}

// End is equivalent to Range().End, but should be preferred if only the end of
// the range is needed.
func (gap GapIterator) End() Key {
	if ns := gap.NextSegment(); ns.Ok() {
		return ns.Start()
	}
	return Functions{}.MaxKey()
}

// IsEmpty returns true if the iterated gap is empty (that is, the "gap" is
// between two adjacent segments.)
func (gap GapIterator) IsEmpty() bool {
	return gap.Range().Length() == 0
}

// PrevSegment returns the segment immediately before the iterated gap. If no
// such segment exists, PrevSegment returns a terminal iterator.
func (gap GapIterator) PrevSegment() Iterator {
	return segmentBeforePosition(gap.node, gap.index)
}

// NextSegment returns the segment immediately after the iterated gap. If no
// such segment exists, NextSegment returns a terminal iterator.
func (gap GapIterator) NextSegment() Iterator {
	return segmentAfterPosition(gap.node, gap.index)
}

// PrevGap returns the iterated gap's predecessor. If no such gap exists,
// PrevGap returns a terminal iterator.
func (gap GapIterator) PrevGap() GapIterator {
	seg := gap.PrevSegment()
	if !seg.Ok() {
		return GapIterator{}
	}
	return seg.PrevGap()
}

// NextGap returns the iterated gap's successor. If no such gap exists, NextGap
// returns a terminal iterator.
func (gap GapIterator) NextGap() GapIterator {
	seg := gap.NextSegment()
	if !seg.Ok() {
		return GapIterator{}
	}
	return seg.NextGap()
}

// NextLargeEnoughGap returns the iterated gap's first next gap with larger
// length than minSize.  If not found, return a terminal gap iterator (does NOT
// include this gap itself).
//
// Precondition: trackGaps must be 1.
func (gap GapIterator) NextLargeEnoughGap(minSize Key) GapIterator {
	if trackGaps != 1 {
		panic("set is not tracking gaps")
	}
	if gap.node != nil && gap.node.hasChildren && gap.index == gap.node.nrSegments {
		// If gap is the trailing gap of an non-leaf node,
		// translate it to the equivalent gap on leaf level.
		gap.node = gap.NextSegment().node
		gap.index = 0
		return gap.nextLargeEnoughGapHelper(minSize)
	}
	return gap.nextLargeEnoughGapHelper(minSize)
}

// nextLargeEnoughGapHelper is the helper function used by NextLargeEnoughGap
// to do the real recursions.
//
// Preconditions: gap is NOT the trailing gap of a non-leaf node.
func (gap GapIterator) nextLargeEnoughGapHelper(minSize Key) GapIterator {
	for {
		// Crawl up the tree if no large enough gap in current node or the
		// current gap is the trailing one on leaf level.
		for gap.node != nil &&
			(gap.node.maxGap.Get() < minSize || (!gap.node.hasChildren && gap.index == gap.node.nrSegments)) {
			gap.node, gap.index = gap.node.parent, gap.node.parentIndex
		}
		// If no large enough gap throughout the whole set, return a terminal
		// gap iterator.
		if gap.node == nil {
			return GapIterator{}
		}
		// Iterate subsequent gaps.
		gap.index++
		for gap.index <= gap.node.nrSegments {
			if gap.node.hasChildren {
				if largeEnoughGap := gap.node.children[gap.index].searchFirstLargeEnoughGap(minSize); largeEnoughGap.Ok() {
					return largeEnoughGap
				}
			} else {
				if gap.Range().Length() >= minSize {
					return gap
				}
			}
			gap.index++
		}
		gap.node, gap.index = gap.node.parent, gap.node.parentIndex
		if gap.node != nil && gap.index == gap.node.nrSegments {
			// If gap is the trailing gap of a non-leaf node, crawl up to
			// parent again and do recursion.
			gap.node, gap.index = gap.node.parent, gap.node.parentIndex
		}
	}
}

// PrevLargeEnoughGap returns the iterated gap's first prev gap with larger or
// equal length than minSize.  If not found, return a terminal gap iterator
// (does NOT include this gap itself).
//
// Precondition: trackGaps must be 1.
func (gap GapIterator) PrevLargeEnoughGap(minSize Key) GapIterator {
	if trackGaps != 1 {
		panic("set is not tracking gaps")
	}
	if gap.node != nil && gap.node.hasChildren && gap.index == 0 {
		// If gap is the first gap of an non-leaf node,
		// translate it to the equivalent gap on leaf level.
		gap.node = gap.PrevSegment().node
		gap.index = gap.node.nrSegments
		return gap.prevLargeEnoughGapHelper(minSize)
	}
	return gap.prevLargeEnoughGapHelper(minSize)
}

// prevLargeEnoughGapHelper is the helper function used by PrevLargeEnoughGap
// to do the real recursions.
//
// Preconditions: gap is NOT the first gap of a non-leaf node.
func (gap GapIterator) prevLargeEnoughGapHelper(minSize Key) GapIterator {
	for {
		// Crawl up the tree if no large enough gap in current node or the
		// current gap is the first one on leaf level.
		for gap.node != nil &&
			(gap.node.maxGap.Get() < minSize || (!gap.node.hasChildren && gap.index == 0)) {
			gap.node, gap.index = gap.node.parent, gap.node.parentIndex
		}
		// If no large enough gap throughout the whole set, return a terminal
		// gap iterator.
		if gap.node == nil {
			return GapIterator{}
		}
		// Iterate previous gaps.
		gap.index--
		for gap.index >= 0 {
			if gap.node.hasChildren {
				if largeEnoughGap := gap.node.children[gap.index].searchLastLargeEnoughGap(minSize); largeEnoughGap.Ok() {
					return largeEnoughGap
				}
			} else {
				if gap.Range().Length() >= minSize {
					return gap
				}
			}
			gap.index--
		}
		gap.node, gap.index = gap.node.parent, gap.node.parentIndex
		if gap.node != nil && gap.index == 0 {
			// If gap is the first gap of a non-leaf node, crawl up to
			// parent again and do recursion.
			gap.node, gap.index = gap.node.parent, gap.node.parentIndex
		}
	}
}

// segmentBeforePosition returns the predecessor segment of the position given
// by n.children[i], which may or may not contain a child. If no such segment
// exists, segmentBeforePosition returns a terminal iterator.
func segmentBeforePosition(n *node, i int) Iterator {
	for i == 0 {
		if n.parent == nil {
			return Iterator{}
		}
		n, i = n.parent, n.parentIndex
	}
	return Iterator{n, i - 1}
}

// segmentAfterPosition returns the successor segment of the position given by
// n.children[i], which may or may not contain a child. If no such segment
// exists, segmentAfterPosition returns a terminal iterator.
func segmentAfterPosition(n *node, i int) Iterator {
	for i == n.nrSegments {
		if n.parent == nil {
			return Iterator{}
		}
		n, i = n.parent, n.parentIndex
	}
	return Iterator{n, i}
}

func zeroValueSlice(slice []Value) {
	// TODO(jamieliu): check if Go is actually smart enough to optimize a
	// ClearValue that assigns nil to a memset here.
	for i := range slice {
		Functions{}.ClearValue(&slice[i])
	}
}

func zeroNodeSlice(slice []*node) {
	for i := range slice {
		slice[i] = nil
	}
}

// String stringifies a Set for debugging.
func (s *Set) String() string {
	return s.root.String()
}

// String stringifies a node (and all of its children) for debugging.
func (n *node) String() string {
	var buf bytes.Buffer
	n.writeDebugString(&buf, "")
	return buf.String()
}

func (n *node) writeDebugString(buf *bytes.Buffer, prefix string) {
	if n.hasChildren != (n.nrSegments > 0 && n.children[0] != nil) {
		buf.WriteString(prefix)
		fmt.Fprintf(buf, "WARNING: inconsistent value of hasChildren: got %v, want %v\n", n.hasChildren, !n.hasChildren)
	}
	for i := 0; i < n.nrSegments; i++ {
		if child := n.children[i]; child != nil {
			cprefix := fmt.Sprintf("%s- % 3d ", prefix, i)
			if child.parent != n || child.parentIndex != i {
				buf.WriteString(cprefix)
				fmt.Fprintf(buf, "WARNING: inconsistent linkage to parent: got (%p, %d), want (%p, %d)\n", child.parent, child.parentIndex, n, i)
			}
			child.writeDebugString(buf, fmt.Sprintf("%s- % 3d ", prefix, i))
		}
		buf.WriteString(prefix)
		if n.hasChildren {
			if trackGaps != 0 {
				fmt.Fprintf(buf, "- % 3d: %v => %v, maxGap: %d\n", i, n.keys[i], n.values[i], n.maxGap.Get())
			} else {
				fmt.Fprintf(buf, "- % 3d: %v => %v\n", i, n.keys[i], n.values[i])
			}
		} else {
			fmt.Fprintf(buf, "- % 3d: %v => %v\n", i, n.keys[i], n.values[i])
		}
	}
	if child := n.children[n.nrSegments]; child != nil {
		child.writeDebugString(buf, fmt.Sprintf("%s- % 3d ", prefix, n.nrSegments))
	}
}

// FlatSegment represents a segment as a single object. FlatSegment is used as
// an intermediate representation for save/restore and tests.
//
// +stateify savable
type FlatSegment struct {
	Start Key
	End   Key
	Value Value
}

// ExportSlice returns a copy of all segments in the given set, in ascending
// key order.
func (s *Set) ExportSlice() []FlatSegment {
	var fs []FlatSegment
	for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		fs = append(fs, FlatSegment{
			Start: seg.Start(),
			End:   seg.End(),
			Value: seg.Value(),
		})
	}
	return fs
}

// ImportSlice initializes the given set from the given slice.
//
// Preconditions:
//   - s must be empty.
//   - fs must represent a valid set (the segments in fs must have valid
//     lengths that do not overlap).
//   - The segments in fs must be sorted in ascending key order.
func (s *Set) ImportSlice(fs []FlatSegment) error {
	if !s.IsEmpty() {
		return fmt.Errorf("cannot import into non-empty set %v", s)
	}
	gap := s.FirstGap()
	for i := range fs {
		f := &fs[i]
		r := Range{f.Start, f.End}
		if !gap.Range().IsSupersetOf(r) {
			return fmt.Errorf("segment overlaps a preceding segment or is incorrectly sorted: %v => %v", r, f.Value)
		}
		gap = s.InsertWithoutMerging(gap, r, f.Value).NextGap()
	}
	return nil
}

// segmentTestCheck returns an error if s is incorrectly sorted, does not
// contain exactly expectedSegments segments, or contains a segment which
// fails the passed check.
//
// This should be used only for testing, and has been added to this package for
// templating convenience.
func (s *Set) segmentTestCheck(expectedSegments int, segFunc func(int, Range, Value) error) error {
	havePrev := false
	prev := Key(0)
	nrSegments := 0
	for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		next := seg.Start()
		if havePrev && prev >= next {
			return fmt.Errorf("incorrect order: key %d (segment %d) >= key %d (segment %d)", prev, nrSegments-1, next, nrSegments)
		}
		if segFunc != nil {
			if err := segFunc(nrSegments, seg.Range(), seg.Value()); err != nil {
				return err
			}
		}
		prev = next
		havePrev = true
		nrSegments++
	}
	if nrSegments != expectedSegments {
		return fmt.Errorf("incorrect number of segments: got %d, wanted %d", nrSegments, expectedSegments)
	}
	return nil
}

// countSegments counts the number of segments in the set.
//
// Similar to Check, this should only be used for testing.
func (s *Set) countSegments() (segments int) {
	for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		segments++
	}
	return segments
}
