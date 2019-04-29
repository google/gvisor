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

package segment

import (
	"fmt"
	"math/rand"
	"testing"
)

const (
	// testSize is the baseline number of elements inserted into sets under
	// test, and is chosen to be large enough to ensure interesting amounts of
	// tree rebalancing.
	//
	// Note that because checkSet is called between each insertion/removal in
	// some tests that use it, tests may be quadratic in testSize.
	testSize = 8000

	// valueOffset is the difference between the value and start of test
	// segments.
	valueOffset = 100000
)

func shuffle(xs []int) {
	for i := range xs {
		j := rand.Intn(i + 1)
		xs[i], xs[j] = xs[j], xs[i]
	}
}

func randPermutation(size int) []int {
	p := make([]int, size)
	for i := range p {
		p[i] = i
	}
	shuffle(p)
	return p
}

// checkSet returns an error if s is incorrectly sorted, does not contain
// exactly expectedSegments segments, or contains a segment for which val !=
// key + valueOffset.
func checkSet(s *Set, expectedSegments int) error {
	havePrev := false
	prev := 0
	nrSegments := 0
	for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		next := seg.Start()
		if havePrev && prev >= next {
			return fmt.Errorf("incorrect order: key %d (segment %d) >= key %d (segment %d)", prev, nrSegments-1, next, nrSegments)
		}
		if got, want := seg.Value(), seg.Start()+valueOffset; got != want {
			return fmt.Errorf("segment %d has key %d, value %d (expected %d)", nrSegments, seg.Start, got, want)
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

// countSegmentsIn returns the number of segments in s.
func countSegmentsIn(s *Set) int {
	var count int
	for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		count++
	}
	return count
}

func TestAddRandom(t *testing.T) {
	var s Set
	order := randPermutation(testSize)
	var nrInsertions int
	for i, j := range order {
		if !s.AddWithoutMerging(Range{j, j + 1}, j+valueOffset) {
			t.Errorf("Iteration %d: failed to insert segment with key %d", i, j)
			break
		}
		nrInsertions++
		if err := checkSet(&s, nrInsertions); err != nil {
			t.Errorf("Iteration %d: %v", i, err)
			break
		}
	}
	if got, want := countSegmentsIn(&s), nrInsertions; got != want {
		t.Errorf("Wrong final number of segments: got %d, wanted %d", got, want)
	}
	if t.Failed() {
		t.Logf("Insertion order: %v", order[:nrInsertions])
		t.Logf("Set contents:\n%v", &s)
	}
}

func TestRemoveRandom(t *testing.T) {
	var s Set
	for i := 0; i < testSize; i++ {
		if !s.AddWithoutMerging(Range{i, i + 1}, i+valueOffset) {
			t.Fatalf("Failed to insert segment %d", i)
		}
	}
	order := randPermutation(testSize)
	var nrRemovals int
	for i, j := range order {
		seg := s.FindSegment(j)
		if !seg.Ok() {
			t.Errorf("Iteration %d: failed to find segment with key %d", i, j)
			break
		}
		s.Remove(seg)
		nrRemovals++
		if err := checkSet(&s, testSize-nrRemovals); err != nil {
			t.Errorf("Iteration %d: %v", i, err)
			break
		}
	}
	if got, want := countSegmentsIn(&s), testSize-nrRemovals; got != want {
		t.Errorf("Wrong final number of segments: got %d, wanted %d", got, want)
	}
	if t.Failed() {
		t.Logf("Removal order: %v", order[:nrRemovals])
		t.Logf("Set contents:\n%v", &s)
		t.FailNow()
	}
}

func TestAddSequentialAdjacent(t *testing.T) {
	var s Set
	var nrInsertions int
	for i := 0; i < testSize; i++ {
		if !s.AddWithoutMerging(Range{i, i + 1}, i+valueOffset) {
			t.Fatalf("Failed to insert segment %d", i)
		}
		nrInsertions++
		if err := checkSet(&s, nrInsertions); err != nil {
			t.Errorf("Iteration %d: %v", i, err)
			break
		}
	}
	if got, want := countSegmentsIn(&s), nrInsertions; got != want {
		t.Errorf("Wrong final number of segments: got %d, wanted %d", got, want)
	}
	if t.Failed() {
		t.Logf("Set contents:\n%v", &s)
	}

	first := s.FirstSegment()
	gotSeg, gotGap := first.PrevNonEmpty()
	if wantGap := s.FirstGap(); gotSeg.Ok() || gotGap != wantGap {
		t.Errorf("FirstSegment().PrevNonEmpty(): got (%v, %v), wanted (<terminal iterator>, %v)", gotSeg, gotGap, wantGap)
	}
	gotSeg, gotGap = first.NextNonEmpty()
	if wantSeg := first.NextSegment(); gotSeg != wantSeg || gotGap.Ok() {
		t.Errorf("FirstSegment().NextNonEmpty(): got (%v, %v), wanted (%v, <terminal iterator>)", gotSeg, gotGap, wantSeg)
	}

	last := s.LastSegment()
	gotSeg, gotGap = last.PrevNonEmpty()
	if wantSeg := last.PrevSegment(); gotSeg != wantSeg || gotGap.Ok() {
		t.Errorf("LastSegment().PrevNonEmpty(): got (%v, %v), wanted (%v, <terminal iterator>)", gotSeg, gotGap, wantSeg)
	}
	gotSeg, gotGap = last.NextNonEmpty()
	if wantGap := s.LastGap(); gotSeg.Ok() || gotGap != wantGap {
		t.Errorf("LastSegment().NextNonEmpty(): got (%v, %v), wanted (<terminal iterator>, %v)", gotSeg, gotGap, wantGap)
	}

	for seg := first.NextSegment(); seg != last; seg = seg.NextSegment() {
		gotSeg, gotGap = seg.PrevNonEmpty()
		if wantSeg := seg.PrevSegment(); gotSeg != wantSeg || gotGap.Ok() {
			t.Errorf("%v.PrevNonEmpty(): got (%v, %v), wanted (%v, <terminal iterator>)", seg, gotSeg, gotGap, wantSeg)
		}
		gotSeg, gotGap = seg.NextNonEmpty()
		if wantSeg := seg.NextSegment(); gotSeg != wantSeg || gotGap.Ok() {
			t.Errorf("%v.NextNonEmpty(): got (%v, %v), wanted (%v, <terminal iterator>)", seg, gotSeg, gotGap, wantSeg)
		}
	}
}

func TestAddSequentialNonAdjacent(t *testing.T) {
	var s Set
	var nrInsertions int
	for i := 0; i < testSize; i++ {
		// The range here differs from TestAddSequentialAdjacent so that
		// consecutive segments are not adjacent.
		if !s.AddWithoutMerging(Range{2 * i, 2*i + 1}, 2*i+valueOffset) {
			t.Fatalf("Failed to insert segment %d", i)
		}
		nrInsertions++
		if err := checkSet(&s, nrInsertions); err != nil {
			t.Errorf("Iteration %d: %v", i, err)
			break
		}
	}
	if got, want := countSegmentsIn(&s), nrInsertions; got != want {
		t.Errorf("Wrong final number of segments: got %d, wanted %d", got, want)
	}
	if t.Failed() {
		t.Logf("Set contents:\n%v", &s)
	}

	for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		gotSeg, gotGap := seg.PrevNonEmpty()
		if wantGap := seg.PrevGap(); gotSeg.Ok() || gotGap != wantGap {
			t.Errorf("%v.PrevNonEmpty(): got (%v, %v), wanted (<terminal iterator>, %v)", seg, gotSeg, gotGap, wantGap)
		}
		gotSeg, gotGap = seg.NextNonEmpty()
		if wantGap := seg.NextGap(); gotSeg.Ok() || gotGap != wantGap {
			t.Errorf("%v.NextNonEmpty(): got (%v, %v), wanted (<terminal iterator>, %v)", seg, gotSeg, gotGap, wantGap)
		}
	}
}

func TestMergeSplit(t *testing.T) {
	tests := []struct {
		name      string
		initial   []Range
		split     bool
		splitAddr int
		final     []Range
	}{
		{
			name:    "Add merges after existing segment",
			initial: []Range{{1000, 1100}, {1100, 1200}},
			final:   []Range{{1000, 1200}},
		},
		{
			name:    "Add merges before existing segment",
			initial: []Range{{1100, 1200}, {1000, 1100}},
			final:   []Range{{1000, 1200}},
		},
		{
			name:    "Add merges between existing segments",
			initial: []Range{{1000, 1100}, {1200, 1300}, {1100, 1200}},
			final:   []Range{{1000, 1300}},
		},
		{
			name:      "SplitAt does nothing at a free address",
			initial:   []Range{{100, 200}},
			split:     true,
			splitAddr: 300,
			final:     []Range{{100, 200}},
		},
		{
			name:      "SplitAt does nothing at the beginning of a segment",
			initial:   []Range{{100, 200}},
			split:     true,
			splitAddr: 100,
			final:     []Range{{100, 200}},
		},
		{
			name:      "SplitAt does nothing at the end of a segment",
			initial:   []Range{{100, 200}},
			split:     true,
			splitAddr: 200,
			final:     []Range{{100, 200}},
		},
		{
			name:      "SplitAt splits in the middle of a segment",
			initial:   []Range{{100, 200}},
			split:     true,
			splitAddr: 150,
			final:     []Range{{100, 150}, {150, 200}},
		},
	}
Tests:
	for _, test := range tests {
		var s Set
		for _, r := range test.initial {
			if !s.Add(r, 0) {
				t.Errorf("%s: Add(%v) failed; set contents:\n%v", test.name, r, &s)
				continue Tests
			}
		}
		if test.split {
			s.SplitAt(test.splitAddr)
		}
		var i int
		for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			if i > len(test.final) {
				t.Errorf("%s: Incorrect number of segments: got %d, wanted %d; set contents:\n%v", test.name, countSegmentsIn(&s), len(test.final), &s)
				continue Tests
			}
			if got, want := seg.Range(), test.final[i]; got != want {
				t.Errorf("%s: Segment %d mismatch: got %v, wanted %v; set contents:\n%v", test.name, i, got, want, &s)
				continue Tests
			}
			i++
		}
		if i < len(test.final) {
			t.Errorf("%s: Incorrect number of segments: got %d, wanted %d; set contents:\n%v", test.name, i, len(test.final), &s)
		}
	}
}

func TestIsolate(t *testing.T) {
	tests := []struct {
		name    string
		initial Range
		bounds  Range
		final   []Range
	}{
		{
			name:    "Isolate does not split a segment that falls inside bounds",
			initial: Range{100, 200},
			bounds:  Range{100, 200},
			final:   []Range{{100, 200}},
		},
		{
			name:    "Isolate splits at beginning of segment",
			initial: Range{50, 200},
			bounds:  Range{100, 200},
			final:   []Range{{50, 100}, {100, 200}},
		},
		{
			name:    "Isolate splits at end of segment",
			initial: Range{100, 250},
			bounds:  Range{100, 200},
			final:   []Range{{100, 200}, {200, 250}},
		},
		{
			name:    "Isolate splits at beginning and end of segment",
			initial: Range{50, 250},
			bounds:  Range{100, 200},
			final:   []Range{{50, 100}, {100, 200}, {200, 250}},
		},
	}
Tests:
	for _, test := range tests {
		var s Set
		seg := s.Insert(s.FirstGap(), test.initial, 0)
		seg = s.Isolate(seg, test.bounds)
		if !test.bounds.IsSupersetOf(seg.Range()) {
			t.Errorf("%s: Isolated segment %v lies outside bounds %v; set contents:\n%v", test.name, seg.Range(), test.bounds, &s)
		}
		var i int
		for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			if i > len(test.final) {
				t.Errorf("%s: Incorrect number of segments: got %d, wanted %d; set contents:\n%v", test.name, countSegmentsIn(&s), len(test.final), &s)
				continue Tests
			}
			if got, want := seg.Range(), test.final[i]; got != want {
				t.Errorf("%s: Segment %d mismatch: got %v, wanted %v; set contents:\n%v", test.name, i, got, want, &s)
				continue Tests
			}
			i++
		}
		if i < len(test.final) {
			t.Errorf("%s: Incorrect number of segments: got %d, wanted %d; set contents:\n%v", test.name, i, len(test.final), &s)
		}
	}
}

func benchmarkAddSequential(b *testing.B, size int) {
	for n := 0; n < b.N; n++ {
		var s Set
		for i := 0; i < size; i++ {
			if !s.AddWithoutMerging(Range{i, i + 1}, i) {
				b.Fatalf("Failed to insert segment %d", i)
			}
		}
	}
}

func benchmarkAddRandom(b *testing.B, size int) {
	order := randPermutation(size)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		var s Set
		for _, i := range order {
			if !s.AddWithoutMerging(Range{i, i + 1}, i) {
				b.Fatalf("Failed to insert segment %d", i)
			}
		}
	}
}

func benchmarkFindSequential(b *testing.B, size int) {
	var s Set
	for i := 0; i < size; i++ {
		if !s.AddWithoutMerging(Range{i, i + 1}, i) {
			b.Fatalf("Failed to insert segment %d", i)
		}
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for i := 0; i < size; i++ {
			if seg := s.FindSegment(i); !seg.Ok() {
				b.Fatalf("Failed to find segment %d", i)
			}
		}
	}
}

func benchmarkFindRandom(b *testing.B, size int) {
	var s Set
	for i := 0; i < size; i++ {
		if !s.AddWithoutMerging(Range{i, i + 1}, i) {
			b.Fatalf("Failed to insert segment %d", i)
		}
	}
	order := randPermutation(size)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for _, i := range order {
			if si := s.FindSegment(i); !si.Ok() {
				b.Fatalf("Failed to find segment %d", i)
			}
		}
	}
}

func benchmarkIteration(b *testing.B, size int) {
	var s Set
	for i := 0; i < size; i++ {
		if !s.AddWithoutMerging(Range{i, i + 1}, i) {
			b.Fatalf("Failed to insert segment %d", i)
		}
	}

	b.ResetTimer()
	var count uint64
	for n := 0; n < b.N; n++ {
		for seg := s.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			count++
		}
	}
	if got, want := count, uint64(size)*uint64(b.N); got != want {
		b.Fatalf("Iterated wrong number of segments: got %d, wanted %d", got, want)
	}
}

func benchmarkAddFindRemoveSequential(b *testing.B, size int) {
	for n := 0; n < b.N; n++ {
		var s Set
		for i := 0; i < size; i++ {
			if !s.AddWithoutMerging(Range{i, i + 1}, i) {
				b.Fatalf("Failed to insert segment %d", i)
			}
		}
		for i := 0; i < size; i++ {
			seg := s.FindSegment(i)
			if !seg.Ok() {
				b.Fatalf("Failed to find segment %d", i)
			}
			s.Remove(seg)
		}
		if !s.IsEmpty() {
			b.Fatalf("Set not empty after all removals:\n%v", &s)
		}
	}
}

func benchmarkAddFindRemoveRandom(b *testing.B, size int) {
	order := randPermutation(size)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		var s Set
		for _, i := range order {
			if !s.AddWithoutMerging(Range{i, i + 1}, i) {
				b.Fatalf("Failed to insert segment %d", i)
			}
		}
		for _, i := range order {
			seg := s.FindSegment(i)
			if !seg.Ok() {
				b.Fatalf("Failed to find segment %d", i)
			}
			s.Remove(seg)
		}
		if !s.IsEmpty() {
			b.Fatalf("Set not empty after all removals:\n%v", &s)
		}
	}
}

// Although we don't generally expect our segment sets to get this big, they're
// useful for emulating the effect of cache pressure.
var testSizes = []struct {
	desc string
	size int
}{
	{"64", 1 << 6},
	{"256", 1 << 8},
	{"1K", 1 << 10},
	{"4K", 1 << 12},
	{"16K", 1 << 14},
	{"64K", 1 << 16},
}

func BenchmarkAddSequential(b *testing.B) {
	for _, test := range testSizes {
		b.Run(test.desc, func(b *testing.B) {
			benchmarkAddSequential(b, test.size)
		})
	}
}

func BenchmarkAddRandom(b *testing.B) {
	for _, test := range testSizes {
		b.Run(test.desc, func(b *testing.B) {
			benchmarkAddRandom(b, test.size)
		})
	}
}

func BenchmarkFindSequential(b *testing.B) {
	for _, test := range testSizes {
		b.Run(test.desc, func(b *testing.B) {
			benchmarkFindSequential(b, test.size)
		})
	}
}

func BenchmarkFindRandom(b *testing.B) {
	for _, test := range testSizes {
		b.Run(test.desc, func(b *testing.B) {
			benchmarkFindRandom(b, test.size)
		})
	}
}

func BenchmarkIteration(b *testing.B) {
	for _, test := range testSizes {
		b.Run(test.desc, func(b *testing.B) {
			benchmarkIteration(b, test.size)
		})
	}
}

func BenchmarkAddFindRemoveSequential(b *testing.B) {
	for _, test := range testSizes {
		b.Run(test.desc, func(b *testing.B) {
			benchmarkAddFindRemoveSequential(b, test.size)
		})
	}
}

func BenchmarkAddFindRemoveRandom(b *testing.B) {
	for _, test := range testSizes {
		b.Run(test.desc, func(b *testing.B) {
			benchmarkAddFindRemoveRandom(b, test.size)
		})
	}
}
