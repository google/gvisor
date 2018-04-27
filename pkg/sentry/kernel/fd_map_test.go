// Copyright 2018 Google Inc.
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

package kernel

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/filetest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"
)

const (
	// maxFD is the maximum FD to try to create in the map.
	// This number of open files has been seen in the wild.
	maxFD = 2 * 1024
)

func newTestFDMap() *FDMap {
	return &FDMap{
		files: make(map[kdefs.FD]descriptor),
	}
}

// TestFDMapMany allocates maxFD FDs, i.e. maxes out the FDMap,
// until there is no room, then makes sure that NewFDAt works
// and also that if we remove one and add one that works too.
func TestFDMapMany(t *testing.T) {
	file := filetest.NewTestFile(t)
	limitSet := limits.NewLimitSet()
	limitSet.Set(limits.NumberOfFiles, limits.Limit{maxFD, maxFD})

	f := newTestFDMap()
	for i := 0; i < maxFD; i++ {
		if _, err := f.NewFDFrom(0, file, FDFlags{}, limitSet); err != nil {
			t.Fatalf("Allocated %v FDs but wanted to allocate %v", i, maxFD)
		}
	}

	if _, err := f.NewFDFrom(0, file, FDFlags{}, limitSet); err == nil {
		t.Fatalf("f.NewFDFrom(0, r) in full map: got nil, wanted error")
	}

	if err := f.NewFDAt(1, file, FDFlags{}, limitSet); err != nil {
		t.Fatalf("f.NewFDAt(1, r, FDFlags{}): got %v, wanted nil", err)
	}
}

// TestFDMap does a set of simple tests to make sure simple adds,
// removes, GetRefs, and DecRefs work. The ordering is just weird
// enough that a table-driven approach seemed clumsy.
func TestFDMap(t *testing.T) {
	file := filetest.NewTestFile(t)
	limitSet := limits.NewLimitSet()
	limitSet.Set(limits.NumberOfFiles, limits.Limit{1, maxFD})

	f := newTestFDMap()
	if _, err := f.NewFDFrom(0, file, FDFlags{}, limitSet); err != nil {
		t.Fatalf("Adding an FD to an empty 1-size map: got %v, want nil", err)
	}

	if _, err := f.NewFDFrom(0, file, FDFlags{}, limitSet); err == nil {
		t.Fatalf("Adding an FD to a filled 1-size map: got nil, wanted an error")
	}

	largeLimit := limits.Limit{maxFD, maxFD}
	limitSet.Set(limits.NumberOfFiles, largeLimit)

	if fd, err := f.NewFDFrom(0, file, FDFlags{}, limitSet); err != nil {
		t.Fatalf("Adding an FD to a resized map: got %v, want nil", err)
	} else if fd != kdefs.FD(1) {
		t.Fatalf("Added an FD to a resized map: got %v, want 1", fd)
	}

	if err := f.NewFDAt(1, file, FDFlags{}, limitSet); err != nil {
		t.Fatalf("Replacing FD 1 via f.NewFDAt(1, r, FDFlags{}): got %v, wanted nil", err)
	}

	if err := f.NewFDAt(maxFD+1, file, FDFlags{}, limitSet); err == nil {
		t.Fatalf("Using an FD that was too large via f.NewFDAt(%v, r, FDFlags{}): got nil, wanted an error", maxFD+1)
	}

	if ref := f.GetFile(1); ref == nil {
		t.Fatalf("f.GetFile(1): got nil, wanted %v", file)
	}

	if ref := f.GetFile(2); ref != nil {
		t.Fatalf("f.GetFile(2): got a %v, wanted nil", ref)
	}

	ref, ok := f.Remove(1)
	if !ok {
		t.Fatalf("f.Remove(1) for an existing FD: failed, want success")
	}
	ref.DecRef()

	if ref, ok := f.Remove(1); ok {
		ref.DecRef()
		t.Fatalf("r.Remove(1) for a removed FD: got success, want failure")
	}

}

func TestDescriptorFlags(t *testing.T) {
	file := filetest.NewTestFile(t)
	f := newTestFDMap()
	limitSet := limits.NewLimitSet()
	limitSet.Set(limits.NumberOfFiles, limits.Limit{maxFD, maxFD})

	if err := f.NewFDAt(2, file, FDFlags{CloseOnExec: true}, limitSet); err != nil {
		t.Fatalf("f.NewFDAt(2, r, FDFlags{}): got %v, wanted nil", err)
	}

	newFile, flags := f.GetDescriptor(2)
	if newFile == nil {
		t.Fatalf("f.GetFile(2): got a %v, wanted nil", newFile)
	}

	if !flags.CloseOnExec {
		t.Fatalf("new File flags %d don't match original %d\n", flags, 0)
	}
}
