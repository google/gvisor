package memmap

// A Range represents a contiguous range of T.
//
// +stateify savable
type MappableRange struct {
	// Start is the inclusive start of the range.
	Start uint64

	// End is the exclusive end of the range.
	End uint64
}

// WellFormed returns true if r.Start <= r.End. All other methods on a Range
// require that the Range is well-formed.
func (r MappableRange) WellFormed() bool {
	return r.Start <= r.End
}

// Length returns the length of the range.
func (r MappableRange) Length() uint64 {
	return r.End - r.Start
}

// Contains returns true if r contains x.
func (r MappableRange) Contains(x uint64) bool {
	return r.Start <= x && x < r.End
}

// Overlaps returns true if r and r2 overlap.
func (r MappableRange) Overlaps(r2 MappableRange) bool {
	return r.Start < r2.End && r2.Start < r.End
}

// IsSupersetOf returns true if r is a superset of r2; that is, the range r2 is
// contained within r.
func (r MappableRange) IsSupersetOf(r2 MappableRange) bool {
	return r.Start <= r2.Start && r.End >= r2.End
}

// Intersect returns a range consisting of the intersection between r and r2.
// If r and r2 do not overlap, Intersect returns a range with unspecified
// bounds, but for which Length() == 0.
func (r MappableRange) Intersect(r2 MappableRange) MappableRange {
	if r.Start < r2.Start {
		r.Start = r2.Start
	}
	if r.End > r2.End {
		r.End = r2.End
	}
	if r.End < r.Start {
		r.End = r.Start
	}
	return r
}

// CanSplitAt returns true if it is legal to split a segment spanning the range
// r at x; that is, splitting at x would produce two ranges, both of which have
// non-zero length.
func (r MappableRange) CanSplitAt(x uint64) bool {
	return r.Contains(x) && r.Start < x
}
