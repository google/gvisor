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

package kernel

import (
	"runtime"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/context/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/filetest"
	"gvisor.dev/gvisor/pkg/sentry/limits"
)

const (
	// maxFD is the maximum FD to try to create in the map.
	//
	// This number of open files has been seen in the wild.
	maxFD = 2 * 1024
)

func runTest(t testing.TB, fn func(ctx context.Context, fdTable *FDTable, file *fs.File, limitSet *limits.LimitSet)) {
	t.Helper() // Don't show in stacks.

	// Create the limits and context.
	limitSet := limits.NewLimitSet()
	limitSet.Set(limits.NumberOfFiles, limits.Limit{maxFD, maxFD}, true)
	ctx := contexttest.WithLimitSet(contexttest.Context(t), limitSet)

	// Create a test file.;
	file := filetest.NewTestFile(t)

	// Create the table.
	fdTable := new(FDTable)
	fdTable.init()

	// Run the test.
	fn(ctx, fdTable, file, limitSet)
}

// TestFDTableMany allocates maxFD FDs, i.e. maxes out the FDTable, until there
// is no room, then makes sure that NewFDAt works and also that if we remove
// one and add one that works too.
func TestFDTableMany(t *testing.T) {
	runTest(t, func(ctx context.Context, fdTable *FDTable, file *fs.File, _ *limits.LimitSet) {
		for i := 0; i < maxFD; i++ {
			if _, err := fdTable.NewFDs(ctx, 0, []*fs.File{file}, FDFlags{}); err != nil {
				t.Fatalf("Allocated %v FDs but wanted to allocate %v", i, maxFD)
			}
		}

		if _, err := fdTable.NewFDs(ctx, 0, []*fs.File{file}, FDFlags{}); err == nil {
			t.Fatalf("fdTable.NewFDs(0, r) in full map: got nil, wanted error")
		}

		if err := fdTable.NewFDAt(ctx, 1, file, FDFlags{}); err != nil {
			t.Fatalf("fdTable.NewFDAt(1, r, FDFlags{}): got %v, wanted nil", err)
		}

		i := int32(2)
		fdTable.Remove(i)
		if fds, err := fdTable.NewFDs(ctx, 0, []*fs.File{file}, FDFlags{}); err != nil || fds[0] != i {
			t.Fatalf("Allocated %v FDs but wanted to allocate %v: %v", i, maxFD, err)
		}
	})
}

func TestFDTableOverLimit(t *testing.T) {
	runTest(t, func(ctx context.Context, fdTable *FDTable, file *fs.File, _ *limits.LimitSet) {
		if _, err := fdTable.NewFDs(ctx, maxFD, []*fs.File{file}, FDFlags{}); err == nil {
			t.Fatalf("fdTable.NewFDs(maxFD, f): got nil, wanted error")
		}

		if _, err := fdTable.NewFDs(ctx, maxFD-2, []*fs.File{file, file, file}, FDFlags{}); err == nil {
			t.Fatalf("fdTable.NewFDs(maxFD-2, {f,f,f}): got nil, wanted error")
		}

		if fds, err := fdTable.NewFDs(ctx, maxFD-3, []*fs.File{file, file, file}, FDFlags{}); err != nil {
			t.Fatalf("fdTable.NewFDs(maxFD-3, {f,f,f}): got %v, wanted nil", err)
		} else {
			for _, fd := range fds {
				fdTable.Remove(fd)
			}
		}

		if fds, err := fdTable.NewFDs(ctx, maxFD-1, []*fs.File{file}, FDFlags{}); err != nil || fds[0] != maxFD-1 {
			t.Fatalf("fdTable.NewFDAt(1, r, FDFlags{}): got %v, wanted nil", err)
		}

		if fds, err := fdTable.NewFDs(ctx, 0, []*fs.File{file}, FDFlags{}); err != nil {
			t.Fatalf("Adding an FD to a resized map: got %v, want nil", err)
		} else if len(fds) != 1 || fds[0] != 0 {
			t.Fatalf("Added an FD to a resized map: got %v, want {1}", fds)
		}
	})
}

// TestFDTable does a set of simple tests to make sure simple adds, removes,
// GetRefs, and DecRefs work. The ordering is just weird enough that a
// table-driven approach seemed clumsy.
func TestFDTable(t *testing.T) {
	runTest(t, func(ctx context.Context, fdTable *FDTable, file *fs.File, limitSet *limits.LimitSet) {
		// Cap the limit at one.
		limitSet.Set(limits.NumberOfFiles, limits.Limit{1, maxFD}, true)

		if _, err := fdTable.NewFDs(ctx, 0, []*fs.File{file}, FDFlags{}); err != nil {
			t.Fatalf("Adding an FD to an empty 1-size map: got %v, want nil", err)
		}

		if _, err := fdTable.NewFDs(ctx, 0, []*fs.File{file}, FDFlags{}); err == nil {
			t.Fatalf("Adding an FD to a filled 1-size map: got nil, wanted an error")
		}

		// Remove the previous limit.
		limitSet.Set(limits.NumberOfFiles, limits.Limit{maxFD, maxFD}, true)

		if fds, err := fdTable.NewFDs(ctx, 0, []*fs.File{file}, FDFlags{}); err != nil {
			t.Fatalf("Adding an FD to a resized map: got %v, want nil", err)
		} else if len(fds) != 1 || fds[0] != 1 {
			t.Fatalf("Added an FD to a resized map: got %v, want {1}", fds)
		}

		if err := fdTable.NewFDAt(ctx, 1, file, FDFlags{}); err != nil {
			t.Fatalf("Replacing FD 1 via fdTable.NewFDAt(1, r, FDFlags{}): got %v, wanted nil", err)
		}

		if err := fdTable.NewFDAt(ctx, maxFD+1, file, FDFlags{}); err == nil {
			t.Fatalf("Using an FD that was too large via fdTable.NewFDAt(%v, r, FDFlags{}): got nil, wanted an error", maxFD+1)
		}

		if ref, _ := fdTable.Get(1); ref == nil {
			t.Fatalf("fdTable.Get(1): got nil, wanted %v", file)
		}

		if ref, _ := fdTable.Get(2); ref != nil {
			t.Fatalf("fdTable.Get(2): got a %v, wanted nil", ref)
		}

		ref := fdTable.Remove(1)
		if ref == nil {
			t.Fatalf("fdTable.Remove(1) for an existing FD: failed, want success")
		}
		ref.DecRef()

		if ref := fdTable.Remove(1); ref != nil {
			t.Fatalf("r.Remove(1) for a removed FD: got success, want failure")
		}
	})
}

func TestDescriptorFlags(t *testing.T) {
	runTest(t, func(ctx context.Context, fdTable *FDTable, file *fs.File, _ *limits.LimitSet) {
		if err := fdTable.NewFDAt(ctx, 2, file, FDFlags{CloseOnExec: true}); err != nil {
			t.Fatalf("fdTable.NewFDAt(2, r, FDFlags{}): got %v, wanted nil", err)
		}

		newFile, flags := fdTable.Get(2)
		if newFile == nil {
			t.Fatalf("fdTable.Get(2): got a %v, wanted nil", newFile)
		}

		if !flags.CloseOnExec {
			t.Fatalf("new File flags %v don't match original %d\n", flags, 0)
		}
	})
}

func BenchmarkFDLookupAndDecRef(b *testing.B) {
	b.StopTimer() // Setup.

	runTest(b, func(ctx context.Context, fdTable *FDTable, file *fs.File, _ *limits.LimitSet) {
		fds, err := fdTable.NewFDs(ctx, 0, []*fs.File{file, file, file, file, file}, FDFlags{})
		if err != nil {
			b.Fatalf("fdTable.NewFDs: got %v, wanted nil", err)
		}

		b.StartTimer() // Benchmark.
		for i := 0; i < b.N; i++ {
			tf, _ := fdTable.Get(fds[i%len(fds)])
			tf.DecRef()
		}
	})
}

func BenchmarkFDLookupAndDecRefConcurrent(b *testing.B) {
	b.StopTimer() // Setup.

	runTest(b, func(ctx context.Context, fdTable *FDTable, file *fs.File, _ *limits.LimitSet) {
		fds, err := fdTable.NewFDs(ctx, 0, []*fs.File{file, file, file, file, file}, FDFlags{})
		if err != nil {
			b.Fatalf("fdTable.NewFDs: got %v, wanted nil", err)
		}

		concurrency := runtime.GOMAXPROCS(0)
		if concurrency < 4 {
			concurrency = 4
		}
		each := b.N / concurrency

		b.StartTimer() // Benchmark.
		var wg sync.WaitGroup
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < each; i++ {
					tf, _ := fdTable.Get(fds[i%len(fds)])
					tf.DecRef()
				}
			}()
		}
		wg.Wait()
	})
}
