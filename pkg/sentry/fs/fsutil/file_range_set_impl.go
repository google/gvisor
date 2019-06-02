package fsutil

import (
	__generics_imported0 "gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
)

import (
	"bytes"
	"fmt"
)

const (
	// minDegree is the minimum degree of an internal node in a Set B-tree.
	//
	// - Any non-root node has at least minDegree-1 segments.
	//
	// - Any non-root internal (non-leaf) node has at least minDegree children.
	//
	// - The root node may have fewer than minDegree-1 segments, but it may
	// only have 0 segments if the tree is empty.
	//
	// Our implementation requires minDegree >= 3. Higher values of minDegree
	// usually improve performance, but increase memory usage for small sets.
	FileRangeminDegree = 3

	FileRangemaxDegree = 2 * FileRangeminDegree
)

// A Set is a mapping of segments with non-overlapping Range keys. The zero
// value for a Set is an empty set. Set values are not safely movable nor
// copyable. Set is thread-compatible.
//
// +stateify savable
type FileRangeSet struct {
	root FileRangenode `state:".(*FileRangeSegmentDataSlices)"`
}

// IsEmpty returns true if the set contains no segments.
func (s *FileRangeSet) IsEmpty() bool {
	return s.root.nrSegments == 0
}

// IsEmptyRange returns true iff no segments in the set overlap the given
// range. This is semantically equivalent to s.SpanRange(r) == 0, but may be
// more efficient.
func (s *FileRangeSet) IsEmptyRange(r __generics_imported0.MappableRange) bool {
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
func (s *FileRangeSet) Span() uint64 {
	var sz uint64
	for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		sz += seg.Range().Length()
	}
	return sz
}

// SpanRange returns the total size of the intersection of segments in the set
// with the given range.
func (s *FileRangeSet) SpanRange(r __generics_imported0.MappableRange) uint64 {
	switch {
	case r.Length() < 0:
		panic(fmt.Sprintf("invalid range %v", r))
	case r.Length() == 0:
		return 0
	}
	var sz uint64
	for seg := s.LowerBoundSegment(r.Start); seg.Ok() && seg.Start() < r.End; seg = seg.NextSegment() {
		sz += seg.Range().Intersect(r).Length()
	}
	return sz
}

// FirstSegment returns the first segment in the set. If the set is empty,
// FirstSegment returns a terminal iterator.
func (s *FileRangeSet) FirstSegment() FileRangeIterator {
	if s.root.nrSegments == 0 {
		return FileRangeIterator{}
	}
	return s.root.firstSegment()
}

// LastSegment returns the last segment in the set. If the set is empty,
// LastSegment returns a terminal iterator.
func (s *FileRangeSet) LastSegment() FileRangeIterator {
	if s.root.nrSegments == 0 {
		return FileRangeIterator{}
	}
	return s.root.lastSegment()
}

// FirstGap returns the first gap in the set.
func (s *FileRangeSet) FirstGap() FileRangeGapIterator {
	n := &s.root
	for n.hasChildren {
		n = n.children[0]
	}
	return FileRangeGapIterator{n, 0}
}

// LastGap returns the last gap in the set.
func (s *FileRangeSet) LastGap() FileRangeGapIterator {
	n := &s.root
	for n.hasChildren {
		n = n.children[n.nrSegments]
	}
	return FileRangeGapIterator{n, n.nrSegments}
}

// Find returns the segment or gap whose range contains the given key. If a
// segment is found, the returned Iterator is non-terminal and the
// returned GapIterator is terminal. Otherwise, the returned Iterator is
// terminal and the returned GapIterator is non-terminal.
func (s *FileRangeSet) Find(key uint64) (FileRangeIterator, FileRangeGapIterator) {
	n := &s.root
	for {

		lower := 0
		upper := n.nrSegments
		for lower < upper {
			i := lower + (upper-lower)/2
			if r := n.keys[i]; key < r.End {
				if key >= r.Start {
					return FileRangeIterator{n, i}, FileRangeGapIterator{}
				}
				upper = i
			} else {
				lower = i + 1
			}
		}
		i := lower
		if !n.hasChildren {
			return FileRangeIterator{}, FileRangeGapIterator{n, i}
		}
		n = n.children[i]
	}
}

// FindSegment returns the segment whose range contains the given key. If no
// such segment exists, FindSegment returns a terminal iterator.
func (s *FileRangeSet) FindSegment(key uint64) FileRangeIterator {
	seg, _ := s.Find(key)
	return seg
}

// LowerBoundSegment returns the segment with the lowest range that contains a
// key greater than or equal to min. If no such segment exists,
// LowerBoundSegment returns a terminal iterator.
func (s *FileRangeSet) LowerBoundSegment(min uint64) FileRangeIterator {
	seg, gap := s.Find(min)
	if seg.Ok() {
		return seg
	}
	return gap.NextSegment()
}

// UpperBoundSegment returns the segment with the highest range that contains a
// key less than or equal to max. If no such segment exists, UpperBoundSegment
// returns a terminal iterator.
func (s *FileRangeSet) UpperBoundSegment(max uint64) FileRangeIterator {
	seg, gap := s.Find(max)
	if seg.Ok() {
		return seg
	}
	return gap.PrevSegment()
}

// FindGap returns the gap containing the given key. If no such gap exists
// (i.e. the set contains a segment containing that key), FindGap returns a
// terminal iterator.
func (s *FileRangeSet) FindGap(key uint64) FileRangeGapIterator {
	_, gap := s.Find(key)
	return gap
}

// LowerBoundGap returns the gap with the lowest range that is greater than or
// equal to min.
func (s *FileRangeSet) LowerBoundGap(min uint64) FileRangeGapIterator {
	seg, gap := s.Find(min)
	if gap.Ok() {
		return gap
	}
	return seg.NextGap()
}

// UpperBoundGap returns the gap with the highest range that is less than or
// equal to max.
func (s *FileRangeSet) UpperBoundGap(max uint64) FileRangeGapIterator {
	seg, gap := s.Find(max)
	if gap.Ok() {
		return gap
	}
	return seg.PrevGap()
}

// Add inserts the given segment into the set and returns true. If the new
// segment can be merged with adjacent segments, Add will do so. If the new
// segment would overlap an existing segment, Add returns false. If Add
// succeeds, all existing iterators are invalidated.
func (s *FileRangeSet) Add(r __generics_imported0.MappableRange, val uint64) bool {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	gap := s.FindGap(r.Start)
	if !gap.Ok() {
		return false
	}
	if r.End > gap.End() {
		return false
	}
	s.Insert(gap, r, val)
	return true
}

// AddWithoutMerging inserts the given segment into the set and returns true.
// If it would overlap an existing segment, AddWithoutMerging does nothing and
// returns false. If AddWithoutMerging succeeds, all existing iterators are
// invalidated.
func (s *FileRangeSet) AddWithoutMerging(r __generics_imported0.MappableRange, val uint64) bool {
	if r.Length() <= 0 {
		panic(fmt.Sprintf("invalid segment range %v", r))
	}
	gap := s.FindGap(r.Start)
	if !gap.Ok() {
		return false
	}
	if r.End > gap.End() {
		return false
	}
	s.InsertWithoutMergingUnchecked(gap, r, val)
	return true
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
func (s *FileRangeSet) Insert(gap FileRangeGapIterator, r __generics_imported0.MappableRange, val uint64) FileRangeIterator {
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
		if mval, ok := (fileRangeSetFunctions{}).Merge(prev.Range(), prev.Value(), r, val); ok {
			prev.SetEndUnchecked(r.End)
			prev.SetValue(mval)
			if next.Ok() && next.Start() == r.End {
				val = mval
				if mval, ok := (fileRangeSetFunctions{}).Merge(prev.Range(), val, next.Range(), next.Value()); ok {
					prev.SetEndUnchecked(next.End())
					prev.SetValue(mval)
					return s.Remove(next).PrevSegment()
				}
			}
			return prev
		}
	}
	if next.Ok() && next.Start() == r.End {
		if mval, ok := (fileRangeSetFunctions{}).Merge(r, val, next.Range(), next.Value()); ok {
			next.SetStartUnchecked(r.Start)
			next.SetValue(mval)
			return next
		}
	}
	return s.InsertWithoutMergingUnchecked(gap, r, val)
}

// InsertWithoutMerging inserts the given segment into the given gap and
// returns an iterator to the inserted segment. All existing iterators
// (including gap, but not including the returned iterator) are invalidated.
//
// If the gap cannot accommodate the segment, or if r is invalid,
// InsertWithoutMerging panics.
func (s *FileRangeSet) InsertWithoutMerging(gap FileRangeGapIterator, r __generics_imported0.MappableRange, val uint64) FileRangeIterator {
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
// Preconditions: r.Start >= gap.Start(); r.End <= gap.End().
func (s *FileRangeSet) InsertWithoutMergingUnchecked(gap FileRangeGapIterator, r __generics_imported0.MappableRange, val uint64) FileRangeIterator {
	gap = gap.node.rebalanceBeforeInsert(gap)
	copy(gap.node.keys[gap.index+1:], gap.node.keys[gap.index:gap.node.nrSegments])
	copy(gap.node.values[gap.index+1:], gap.node.values[gap.index:gap.node.nrSegments])
	gap.node.keys[gap.index] = r
	gap.node.values[gap.index] = val
	gap.node.nrSegments++
	return FileRangeIterator{gap.node, gap.index}
}

// Remove removes the given segment and returns an iterator to the vacated gap.
// All existing iterators (including seg, but not including the returned
// iterator) are invalidated.
func (s *FileRangeSet) Remove(seg FileRangeIterator) FileRangeGapIterator {

	if seg.node.hasChildren {

		victim := seg.PrevSegment()

		seg.SetRangeUnchecked(victim.Range())
		seg.SetValue(victim.Value())
		return s.Remove(victim).NextGap()
	}
	copy(seg.node.keys[seg.index:], seg.node.keys[seg.index+1:seg.node.nrSegments])
	copy(seg.node.values[seg.index:], seg.node.values[seg.index+1:seg.node.nrSegments])
	fileRangeSetFunctions{}.ClearValue(&seg.node.values[seg.node.nrSegments-1])
	seg.node.nrSegments--
	return seg.node.rebalanceAfterRemove(FileRangeGapIterator{seg.node, seg.index})
}

// RemoveAll removes all segments from the set. All existing iterators are
// invalidated.
func (s *FileRangeSet) RemoveAll() {
	s.root = FileRangenode{}
}

// RemoveRange removes all segments in the given range. An iterator to the
// newly formed gap is returned, and all existing iterators are invalidated.
func (s *FileRangeSet) RemoveRange(r __generics_imported0.MappableRange) FileRangeGapIterator {
	seg, gap := s.Find(r.Start)
	if seg.Ok() {
		seg = s.Isolate(seg, r)
		gap = s.Remove(seg)
	}
	for seg = gap.NextSegment(); seg.Ok() && seg.Start() < r.End; seg = gap.NextSegment() {
		seg = s.Isolate(seg, r)
		gap = s.Remove(seg)
	}
	return gap
}

// Merge attempts to merge two neighboring segments. If successful, Merge
// returns an iterator to the merged segment, and all existing iterators are
// invalidated. Otherwise, Merge returns a terminal iterator.
//
// If first is not the predecessor of second, Merge panics.
func (s *FileRangeSet) Merge(first, second FileRangeIterator) FileRangeIterator {
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
func (s *FileRangeSet) MergeUnchecked(first, second FileRangeIterator) FileRangeIterator {
	if first.End() == second.Start() {
		if mval, ok := (fileRangeSetFunctions{}).Merge(first.Range(), first.Value(), second.Range(), second.Value()); ok {

			first.SetEndUnchecked(second.End())
			first.SetValue(mval)
			return s.Remove(second).PrevSegment()
		}
	}
	return FileRangeIterator{}
}

// MergeAll attempts to merge all adjacent segments in the set. All existing
// iterators are invalidated.
func (s *FileRangeSet) MergeAll() {
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

// MergeRange attempts to merge all adjacent segments that contain a key in the
// specific range. All existing iterators are invalidated.
func (s *FileRangeSet) MergeRange(r __generics_imported0.MappableRange) {
	seg := s.LowerBoundSegment(r.Start)
	if !seg.Ok() {
		return
	}
	next := seg.NextSegment()
	for next.Ok() && next.Range().Start < r.End {
		if mseg := s.MergeUnchecked(seg, next); mseg.Ok() {
			seg, next = mseg, mseg.NextSegment()
		} else {
			seg, next = next, next.NextSegment()
		}
	}
}

// MergeAdjacent attempts to merge the segment containing r.Start with its
// predecessor, and the segment containing r.End-1 with its successor.
func (s *FileRangeSet) MergeAdjacent(r __generics_imported0.MappableRange) {
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
func (s *FileRangeSet) Split(seg FileRangeIterator, split uint64) (FileRangeIterator, FileRangeIterator) {
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
func (s *FileRangeSet) SplitUnchecked(seg FileRangeIterator, split uint64) (FileRangeIterator, FileRangeIterator) {
	val1, val2 := (fileRangeSetFunctions{}).Split(seg.Range(), seg.Value(), split)
	end2 := seg.End()
	seg.SetEndUnchecked(split)
	seg.SetValue(val1)
	seg2 := s.InsertWithoutMergingUnchecked(seg.NextGap(), __generics_imported0.MappableRange{split, end2}, val2)

	return seg2.PrevSegment(), seg2
}

// SplitAt splits the segment straddling split, if one exists. SplitAt returns
// true if a segment was split and false otherwise. If SplitAt splits a
// segment, all existing iterators are invalidated.
func (s *FileRangeSet) SplitAt(split uint64) bool {
	if seg := s.FindSegment(split); seg.Ok() && seg.Range().CanSplitAt(split) {
		s.SplitUnchecked(seg, split)
		return true
	}
	return false
}

// Isolate ensures that the given segment's range does not escape r by
// splitting at r.Start and r.End if necessary, and returns an updated iterator
// to the bounded segment. All existing iterators (including seg, but not
// including the returned iterators) are invalidated.
func (s *FileRangeSet) Isolate(seg FileRangeIterator, r __generics_imported0.MappableRange) FileRangeIterator {
	if seg.Range().CanSplitAt(r.Start) {
		_, seg = s.SplitUnchecked(seg, r.Start)
	}
	if seg.Range().CanSplitAt(r.End) {
		seg, _ = s.SplitUnchecked(seg, r.End)
	}
	return seg
}

// ApplyContiguous applies a function to a contiguous range of segments,
// splitting if necessary. The function is applied until the first gap is
// encountered, at which point the gap is returned. If the function is applied
// across the entire range, a terminal gap is returned. All existing iterators
// are invalidated.
//
// N.B. The Iterator must not be invalidated by the function.
func (s *FileRangeSet) ApplyContiguous(r __generics_imported0.MappableRange, fn func(seg FileRangeIterator)) FileRangeGapIterator {
	seg, gap := s.Find(r.Start)
	if !seg.Ok() {
		return gap
	}
	for {
		seg = s.Isolate(seg, r)
		fn(seg)
		if seg.End() >= r.End {
			return FileRangeGapIterator{}
		}
		gap = seg.NextGap()
		if !gap.IsEmpty() {
			return gap
		}
		seg = gap.NextSegment()
		if !seg.Ok() {

			return FileRangeGapIterator{}
		}
	}
}

// +stateify savable
type FileRangenode struct {
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
	parent *FileRangenode

	// parentIndex is the index of this node in parent.children.
	parentIndex int

	// Flag for internal nodes that is technically redundant with "children[0]
	// != nil", but is stored in the first cache line. "hasChildren" rather
	// than "isLeaf" because false must be the correct value for an empty root.
	hasChildren bool

	// Nodes store keys and values in separate arrays to maximize locality in
	// the common case (scanning keys for lookup).
	keys     [FileRangemaxDegree - 1]__generics_imported0.MappableRange
	values   [FileRangemaxDegree - 1]uint64
	children [FileRangemaxDegree]*FileRangenode
}

// firstSegment returns the first segment in the subtree rooted by n.
//
// Preconditions: n.nrSegments != 0.
func (n *FileRangenode) firstSegment() FileRangeIterator {
	for n.hasChildren {
		n = n.children[0]
	}
	return FileRangeIterator{n, 0}
}

// lastSegment returns the last segment in the subtree rooted by n.
//
// Preconditions: n.nrSegments != 0.
func (n *FileRangenode) lastSegment() FileRangeIterator {
	for n.hasChildren {
		n = n.children[n.nrSegments]
	}
	return FileRangeIterator{n, n.nrSegments - 1}
}

func (n *FileRangenode) prevSibling() *FileRangenode {
	if n.parent == nil || n.parentIndex == 0 {
		return nil
	}
	return n.parent.children[n.parentIndex-1]
}

func (n *FileRangenode) nextSibling() *FileRangenode {
	if n.parent == nil || n.parentIndex == n.parent.nrSegments {
		return nil
	}
	return n.parent.children[n.parentIndex+1]
}

// rebalanceBeforeInsert splits n and its ancestors if they are full, as
// required for insertion, and returns an updated iterator to the position
// represented by gap.
func (n *FileRangenode) rebalanceBeforeInsert(gap FileRangeGapIterator) FileRangeGapIterator {
	if n.parent != nil {
		gap = n.parent.rebalanceBeforeInsert(gap)
	}
	if n.nrSegments < FileRangemaxDegree-1 {
		return gap
	}
	if n.parent == nil {

		left := &FileRangenode{
			nrSegments:  FileRangeminDegree - 1,
			parent:      n,
			parentIndex: 0,
			hasChildren: n.hasChildren,
		}
		right := &FileRangenode{
			nrSegments:  FileRangeminDegree - 1,
			parent:      n,
			parentIndex: 1,
			hasChildren: n.hasChildren,
		}
		copy(left.keys[:FileRangeminDegree-1], n.keys[:FileRangeminDegree-1])
		copy(left.values[:FileRangeminDegree-1], n.values[:FileRangeminDegree-1])
		copy(right.keys[:FileRangeminDegree-1], n.keys[FileRangeminDegree:])
		copy(right.values[:FileRangeminDegree-1], n.values[FileRangeminDegree:])
		n.keys[0], n.values[0] = n.keys[FileRangeminDegree-1], n.values[FileRangeminDegree-1]
		FileRangezeroValueSlice(n.values[1:])
		if n.hasChildren {
			copy(left.children[:FileRangeminDegree], n.children[:FileRangeminDegree])
			copy(right.children[:FileRangeminDegree], n.children[FileRangeminDegree:])
			FileRangezeroNodeSlice(n.children[2:])
			for i := 0; i < FileRangeminDegree; i++ {
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
		if gap.node != n {
			return gap
		}
		if gap.index < FileRangeminDegree {
			return FileRangeGapIterator{left, gap.index}
		}
		return FileRangeGapIterator{right, gap.index - FileRangeminDegree}
	}

	copy(n.parent.keys[n.parentIndex+1:], n.parent.keys[n.parentIndex:n.parent.nrSegments])
	copy(n.parent.values[n.parentIndex+1:], n.parent.values[n.parentIndex:n.parent.nrSegments])
	n.parent.keys[n.parentIndex], n.parent.values[n.parentIndex] = n.keys[FileRangeminDegree-1], n.values[FileRangeminDegree-1]
	copy(n.parent.children[n.parentIndex+2:], n.parent.children[n.parentIndex+1:n.parent.nrSegments+1])
	for i := n.parentIndex + 2; i < n.parent.nrSegments+2; i++ {
		n.parent.children[i].parentIndex = i
	}
	sibling := &FileRangenode{
		nrSegments:  FileRangeminDegree - 1,
		parent:      n.parent,
		parentIndex: n.parentIndex + 1,
		hasChildren: n.hasChildren,
	}
	n.parent.children[n.parentIndex+1] = sibling
	n.parent.nrSegments++
	copy(sibling.keys[:FileRangeminDegree-1], n.keys[FileRangeminDegree:])
	copy(sibling.values[:FileRangeminDegree-1], n.values[FileRangeminDegree:])
	FileRangezeroValueSlice(n.values[FileRangeminDegree-1:])
	if n.hasChildren {
		copy(sibling.children[:FileRangeminDegree], n.children[FileRangeminDegree:])
		FileRangezeroNodeSlice(n.children[FileRangeminDegree:])
		for i := 0; i < FileRangeminDegree; i++ {
			sibling.children[i].parent = sibling
			sibling.children[i].parentIndex = i
		}
	}
	n.nrSegments = FileRangeminDegree - 1

	if gap.node != n {
		return gap
	}
	if gap.index < FileRangeminDegree {
		return gap
	}
	return FileRangeGapIterator{sibling, gap.index - FileRangeminDegree}
}

// rebalanceAfterRemove "unsplits" n and its ancestors if they are deficient
// (contain fewer segments than required by B-tree invariants), as required for
// removal, and returns an updated iterator to the position represented by gap.
//
// Precondition: n is the only node in the tree that may currently violate a
// B-tree invariant.
func (n *FileRangenode) rebalanceAfterRemove(gap FileRangeGapIterator) FileRangeGapIterator {
	for {
		if n.nrSegments >= FileRangeminDegree-1 {
			return gap
		}
		if n.parent == nil {

			return gap
		}

		if sibling := n.prevSibling(); sibling != nil && sibling.nrSegments >= FileRangeminDegree {
			copy(n.keys[1:], n.keys[:n.nrSegments])
			copy(n.values[1:], n.values[:n.nrSegments])
			n.keys[0] = n.parent.keys[n.parentIndex-1]
			n.values[0] = n.parent.values[n.parentIndex-1]
			n.parent.keys[n.parentIndex-1] = sibling.keys[sibling.nrSegments-1]
			n.parent.values[n.parentIndex-1] = sibling.values[sibling.nrSegments-1]
			fileRangeSetFunctions{}.ClearValue(&sibling.values[sibling.nrSegments-1])
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
			if gap.node == sibling && gap.index == sibling.nrSegments {
				return FileRangeGapIterator{n, 0}
			}
			if gap.node == n {
				return FileRangeGapIterator{n, gap.index + 1}
			}
			return gap
		}
		if sibling := n.nextSibling(); sibling != nil && sibling.nrSegments >= FileRangeminDegree {
			n.keys[n.nrSegments] = n.parent.keys[n.parentIndex]
			n.values[n.nrSegments] = n.parent.values[n.parentIndex]
			n.parent.keys[n.parentIndex] = sibling.keys[0]
			n.parent.values[n.parentIndex] = sibling.values[0]
			copy(sibling.keys[:sibling.nrSegments-1], sibling.keys[1:])
			copy(sibling.values[:sibling.nrSegments-1], sibling.values[1:])
			fileRangeSetFunctions{}.ClearValue(&sibling.values[sibling.nrSegments-1])
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
			if gap.node == sibling {
				if gap.index == 0 {
					return FileRangeGapIterator{n, n.nrSegments}
				}
				return FileRangeGapIterator{sibling, gap.index - 1}
			}
			return gap
		}

		p := n.parent
		if p.nrSegments == 1 {

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
			if gap.node == left {
				return FileRangeGapIterator{p, gap.index}
			}
			if gap.node == right {
				return FileRangeGapIterator{p, gap.index + left.nrSegments + 1}
			}
			return gap
		}
		// Merge n and either sibling, along with the segment separating the
		// two, into whichever of the two nodes comes first. This is the
		// reverse of the non-root splitting case in
		// node.rebalanceBeforeInsert.
		var left, right *FileRangenode
		if n.parentIndex > 0 {
			left = n.prevSibling()
			right = n
		} else {
			left = n
			right = n.nextSibling()
		}

		if gap.node == right {
			gap = FileRangeGapIterator{left, gap.index + left.nrSegments + 1}
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
		fileRangeSetFunctions{}.ClearValue(&p.values[p.nrSegments-1])
		copy(p.children[left.parentIndex+1:], p.children[left.parentIndex+2:p.nrSegments+1])
		for i := 0; i < p.nrSegments; i++ {
			p.children[i].parentIndex = i
		}
		p.children[p.nrSegments] = nil
		p.nrSegments--

		n = p
	}
}

// A Iterator is conceptually one of:
//
// - A pointer to a segment in a set; or
//
// - A terminal iterator, which is a sentinel indicating that the end of
// iteration has been reached.
//
// Iterators are copyable values and are meaningfully equality-comparable. The
// zero value of Iterator is a terminal iterator.
//
// Unless otherwise specified, any mutation of a set invalidates all existing
// iterators into the set.
type FileRangeIterator struct {
	// node is the node containing the iterated segment. If the iterator is
	// terminal, node is nil.
	node *FileRangenode

	// index is the index of the segment in node.keys/values.
	index int
}

// Ok returns true if the iterator is not terminal. All other methods are only
// valid for non-terminal iterators.
func (seg FileRangeIterator) Ok() bool {
	return seg.node != nil
}

// Range returns the iterated segment's range key.
func (seg FileRangeIterator) Range() __generics_imported0.MappableRange {
	return seg.node.keys[seg.index]
}

// Start is equivalent to Range().Start, but should be preferred if only the
// start of the range is needed.
func (seg FileRangeIterator) Start() uint64 {
	return seg.node.keys[seg.index].Start
}

// End is equivalent to Range().End, but should be preferred if only the end of
// the range is needed.
func (seg FileRangeIterator) End() uint64 {
	return seg.node.keys[seg.index].End
}

// SetRangeUnchecked mutates the iterated segment's range key. This operation
// does not invalidate any iterators.
//
// Preconditions:
//
// - r.Length() > 0.
//
// - The new range must not overlap an existing one: If seg.NextSegment().Ok(),
// then r.end <= seg.NextSegment().Start(); if seg.PrevSegment().Ok(), then
// r.start >= seg.PrevSegment().End().
func (seg FileRangeIterator) SetRangeUnchecked(r __generics_imported0.MappableRange) {
	seg.node.keys[seg.index] = r
}

// SetRange mutates the iterated segment's range key. If the new range would
// cause the iterated segment to overlap another segment, or if the new range
// is invalid, SetRange panics. This operation does not invalidate any
// iterators.
func (seg FileRangeIterator) SetRange(r __generics_imported0.MappableRange) {
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
// Preconditions: The new start must be valid: start < seg.End(); if
// seg.PrevSegment().Ok(), then start >= seg.PrevSegment().End().
func (seg FileRangeIterator) SetStartUnchecked(start uint64) {
	seg.node.keys[seg.index].Start = start
}

// SetStart mutates the iterated segment's start. If the new start value would
// cause the iterated segment to overlap another segment, or would result in an
// invalid range, SetStart panics. This operation does not invalidate any
// iterators.
func (seg FileRangeIterator) SetStart(start uint64) {
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
// Preconditions: The new end must be valid: end > seg.Start(); if
// seg.NextSegment().Ok(), then end <= seg.NextSegment().Start().
func (seg FileRangeIterator) SetEndUnchecked(end uint64) {
	seg.node.keys[seg.index].End = end
}

// SetEnd mutates the iterated segment's end. If the new end value would cause
// the iterated segment to overlap another segment, or would result in an
// invalid range, SetEnd panics. This operation does not invalidate any
// iterators.
func (seg FileRangeIterator) SetEnd(end uint64) {
	if end <= seg.Start() {
		panic(fmt.Sprintf("new end %v would invalidate segment range %v", end, seg.Range()))
	}
	if next := seg.NextSegment(); next.Ok() && end > next.Start() {
		panic(fmt.Sprintf("new end %v would cause segment range %v to overlap segment range %v", end, seg.Range(), next.Range()))
	}
	seg.SetEndUnchecked(end)
}

// Value returns a copy of the iterated segment's value.
func (seg FileRangeIterator) Value() uint64 {
	return seg.node.values[seg.index]
}

// ValuePtr returns a pointer to the iterated segment's value. The pointer is
// invalidated if the iterator is invalidated. This operation does not
// invalidate any iterators.
func (seg FileRangeIterator) ValuePtr() *uint64 {
	return &seg.node.values[seg.index]
}

// SetValue mutates the iterated segment's value. This operation does not
// invalidate any iterators.
func (seg FileRangeIterator) SetValue(val uint64) {
	seg.node.values[seg.index] = val
}

// PrevSegment returns the iterated segment's predecessor. If there is no
// preceding segment, PrevSegment returns a terminal iterator.
func (seg FileRangeIterator) PrevSegment() FileRangeIterator {
	if seg.node.hasChildren {
		return seg.node.children[seg.index].lastSegment()
	}
	if seg.index > 0 {
		return FileRangeIterator{seg.node, seg.index - 1}
	}
	if seg.node.parent == nil {
		return FileRangeIterator{}
	}
	return FileRangesegmentBeforePosition(seg.node.parent, seg.node.parentIndex)
}

// NextSegment returns the iterated segment's successor. If there is no
// succeeding segment, NextSegment returns a terminal iterator.
func (seg FileRangeIterator) NextSegment() FileRangeIterator {
	if seg.node.hasChildren {
		return seg.node.children[seg.index+1].firstSegment()
	}
	if seg.index < seg.node.nrSegments-1 {
		return FileRangeIterator{seg.node, seg.index + 1}
	}
	if seg.node.parent == nil {
		return FileRangeIterator{}
	}
	return FileRangesegmentAfterPosition(seg.node.parent, seg.node.parentIndex)
}

// PrevGap returns the gap immediately before the iterated segment.
func (seg FileRangeIterator) PrevGap() FileRangeGapIterator {
	if seg.node.hasChildren {

		return seg.node.children[seg.index].lastSegment().NextGap()
	}
	return FileRangeGapIterator{seg.node, seg.index}
}

// NextGap returns the gap immediately after the iterated segment.
func (seg FileRangeIterator) NextGap() FileRangeGapIterator {
	if seg.node.hasChildren {
		return seg.node.children[seg.index+1].firstSegment().PrevGap()
	}
	return FileRangeGapIterator{seg.node, seg.index + 1}
}

// PrevNonEmpty returns the iterated segment's predecessor if it is adjacent,
// or the gap before the iterated segment otherwise. If seg.Start() ==
// Functions.MinKey(), PrevNonEmpty will return two terminal iterators.
// Otherwise, exactly one of the iterators returned by PrevNonEmpty will be
// non-terminal.
func (seg FileRangeIterator) PrevNonEmpty() (FileRangeIterator, FileRangeGapIterator) {
	gap := seg.PrevGap()
	if gap.Range().Length() != 0 {
		return FileRangeIterator{}, gap
	}
	return gap.PrevSegment(), FileRangeGapIterator{}
}

// NextNonEmpty returns the iterated segment's successor if it is adjacent, or
// the gap after the iterated segment otherwise. If seg.End() ==
// Functions.MaxKey(), NextNonEmpty will return two terminal iterators.
// Otherwise, exactly one of the iterators returned by NextNonEmpty will be
// non-terminal.
func (seg FileRangeIterator) NextNonEmpty() (FileRangeIterator, FileRangeGapIterator) {
	gap := seg.NextGap()
	if gap.Range().Length() != 0 {
		return FileRangeIterator{}, gap
	}
	return gap.NextSegment(), FileRangeGapIterator{}
}

// A GapIterator is conceptually one of:
//
// - A pointer to a position between two segments, before the first segment, or
// after the last segment in a set, called a *gap*; or
//
// - A terminal iterator, which is a sentinel indicating that the end of
// iteration has been reached.
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
type FileRangeGapIterator struct {
	// The representation of a GapIterator is identical to that of an Iterator,
	// except that index corresponds to positions between segments in the same
	// way as for node.children (see comment for node.nrSegments).
	node  *FileRangenode
	index int
}

// Ok returns true if the iterator is not terminal. All other methods are only
// valid for non-terminal iterators.
func (gap FileRangeGapIterator) Ok() bool {
	return gap.node != nil
}

// Range returns the range spanned by the iterated gap.
func (gap FileRangeGapIterator) Range() __generics_imported0.MappableRange {
	return __generics_imported0.MappableRange{gap.Start(), gap.End()}
}

// Start is equivalent to Range().Start, but should be preferred if only the
// start of the range is needed.
func (gap FileRangeGapIterator) Start() uint64 {
	if ps := gap.PrevSegment(); ps.Ok() {
		return ps.End()
	}
	return fileRangeSetFunctions{}.MinKey()
}

// End is equivalent to Range().End, but should be preferred if only the end of
// the range is needed.
func (gap FileRangeGapIterator) End() uint64 {
	if ns := gap.NextSegment(); ns.Ok() {
		return ns.Start()
	}
	return fileRangeSetFunctions{}.MaxKey()
}

// IsEmpty returns true if the iterated gap is empty (that is, the "gap" is
// between two adjacent segments.)
func (gap FileRangeGapIterator) IsEmpty() bool {
	return gap.Range().Length() == 0
}

// PrevSegment returns the segment immediately before the iterated gap. If no
// such segment exists, PrevSegment returns a terminal iterator.
func (gap FileRangeGapIterator) PrevSegment() FileRangeIterator {
	return FileRangesegmentBeforePosition(gap.node, gap.index)
}

// NextSegment returns the segment immediately after the iterated gap. If no
// such segment exists, NextSegment returns a terminal iterator.
func (gap FileRangeGapIterator) NextSegment() FileRangeIterator {
	return FileRangesegmentAfterPosition(gap.node, gap.index)
}

// PrevGap returns the iterated gap's predecessor. If no such gap exists,
// PrevGap returns a terminal iterator.
func (gap FileRangeGapIterator) PrevGap() FileRangeGapIterator {
	seg := gap.PrevSegment()
	if !seg.Ok() {
		return FileRangeGapIterator{}
	}
	return seg.PrevGap()
}

// NextGap returns the iterated gap's successor. If no such gap exists, NextGap
// returns a terminal iterator.
func (gap FileRangeGapIterator) NextGap() FileRangeGapIterator {
	seg := gap.NextSegment()
	if !seg.Ok() {
		return FileRangeGapIterator{}
	}
	return seg.NextGap()
}

// segmentBeforePosition returns the predecessor segment of the position given
// by n.children[i], which may or may not contain a child. If no such segment
// exists, segmentBeforePosition returns a terminal iterator.
func FileRangesegmentBeforePosition(n *FileRangenode, i int) FileRangeIterator {
	for i == 0 {
		if n.parent == nil {
			return FileRangeIterator{}
		}
		n, i = n.parent, n.parentIndex
	}
	return FileRangeIterator{n, i - 1}
}

// segmentAfterPosition returns the successor segment of the position given by
// n.children[i], which may or may not contain a child. If no such segment
// exists, segmentAfterPosition returns a terminal iterator.
func FileRangesegmentAfterPosition(n *FileRangenode, i int) FileRangeIterator {
	for i == n.nrSegments {
		if n.parent == nil {
			return FileRangeIterator{}
		}
		n, i = n.parent, n.parentIndex
	}
	return FileRangeIterator{n, i}
}

func FileRangezeroValueSlice(slice []uint64) {

	for i := range slice {
		fileRangeSetFunctions{}.ClearValue(&slice[i])
	}
}

func FileRangezeroNodeSlice(slice []*FileRangenode) {
	for i := range slice {
		slice[i] = nil
	}
}

// String stringifies a Set for debugging.
func (s *FileRangeSet) String() string {
	return s.root.String()
}

// String stringifes a node (and all of its children) for debugging.
func (n *FileRangenode) String() string {
	var buf bytes.Buffer
	n.writeDebugString(&buf, "")
	return buf.String()
}

func (n *FileRangenode) writeDebugString(buf *bytes.Buffer, prefix string) {
	if n.hasChildren != (n.nrSegments > 0 && n.children[0] != nil) {
		buf.WriteString(prefix)
		buf.WriteString(fmt.Sprintf("WARNING: inconsistent value of hasChildren: got %v, want %v\n", n.hasChildren, !n.hasChildren))
	}
	for i := 0; i < n.nrSegments; i++ {
		if child := n.children[i]; child != nil {
			cprefix := fmt.Sprintf("%s- % 3d ", prefix, i)
			if child.parent != n || child.parentIndex != i {
				buf.WriteString(cprefix)
				buf.WriteString(fmt.Sprintf("WARNING: inconsistent linkage to parent: got (%p, %d), want (%p, %d)\n", child.parent, child.parentIndex, n, i))
			}
			child.writeDebugString(buf, fmt.Sprintf("%s- % 3d ", prefix, i))
		}
		buf.WriteString(prefix)
		buf.WriteString(fmt.Sprintf("- % 3d: %v => %v\n", i, n.keys[i], n.values[i]))
	}
	if child := n.children[n.nrSegments]; child != nil {
		child.writeDebugString(buf, fmt.Sprintf("%s- % 3d ", prefix, n.nrSegments))
	}
}

// SegmentDataSlices represents segments from a set as slices of start, end, and
// values. SegmentDataSlices is primarily used as an intermediate representation
// for save/restore and the layout here is optimized for that.
//
// +stateify savable
type FileRangeSegmentDataSlices struct {
	Start  []uint64
	End    []uint64
	Values []uint64
}

// ExportSortedSlice returns a copy of all segments in the given set, in ascending
// key order.
func (s *FileRangeSet) ExportSortedSlices() *FileRangeSegmentDataSlices {
	var sds FileRangeSegmentDataSlices
	for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		sds.Start = append(sds.Start, seg.Start())
		sds.End = append(sds.End, seg.End())
		sds.Values = append(sds.Values, seg.Value())
	}
	sds.Start = sds.Start[:len(sds.Start):len(sds.Start)]
	sds.End = sds.End[:len(sds.End):len(sds.End)]
	sds.Values = sds.Values[:len(sds.Values):len(sds.Values)]
	return &sds
}

// ImportSortedSlice initializes the given set from the given slice.
//
// Preconditions: s must be empty. sds must represent a valid set (the segments
// in sds must have valid lengths that do not overlap). The segments in sds
// must be sorted in ascending key order.
func (s *FileRangeSet) ImportSortedSlices(sds *FileRangeSegmentDataSlices) error {
	if !s.IsEmpty() {
		return fmt.Errorf("cannot import into non-empty set %v", s)
	}
	gap := s.FirstGap()
	for i := range sds.Start {
		r := __generics_imported0.MappableRange{sds.Start[i], sds.End[i]}
		if !gap.Range().IsSupersetOf(r) {
			return fmt.Errorf("segment overlaps a preceding segment or is incorrectly sorted: [%d, %d) => %v", sds.Start[i], sds.End[i], sds.Values[i])
		}
		gap = s.InsertWithoutMerging(gap, r, sds.Values[i]).NextGap()
	}
	return nil
}
func (s *FileRangeSet) saveRoot() *FileRangeSegmentDataSlices {
	return s.ExportSortedSlices()
}

func (s *FileRangeSet) loadRoot(sds *FileRangeSegmentDataSlices) {
	if err := s.ImportSortedSlices(sds); err != nil {
		panic(err)
	}
}
