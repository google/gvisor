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

package kernel

import (
	"runtime"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// maxFD is the maximum FD to try to create in the map.
	//
	// This number of open files has been seen in the wild.
	maxFD = 2 * 1024
)

// testFD is a read-only FileDescriptionImpl representing a regular file.
type testFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
}

// Release implements FileDescriptionImpl.Release.
func (fd *testFD) Release(context.Context) {}

func newTestFD(ctx context.Context, vfsObj *vfs.VirtualFilesystem) *vfs.FileDescription {
	vd := vfsObj.NewAnonVirtualDentry("testFD")
	defer vd.DecRef(ctx)
	var fd testFD
	fd.vfsfd.Init(&fd, 0 /* flags */, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{})
	return &fd.vfsfd
}

func runTest(t testing.TB, fn func(ctx context.Context, fdTable *FDTable, fd *vfs.FileDescription, limitSet *limits.LimitSet)) {
	t.Helper() // Don't show in stacks.

	// Create the limits and context.
	limitSet := limits.NewLimitSet()
	limitSet.Set(limits.NumberOfFiles, limits.Limit{maxFD, maxFD}, true)
	ctx := contexttest.WithLimitSet(contexttest.Context(t), limitSet)

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}

	fd := newTestFD(ctx, vfsObj)
	defer fd.DecRef(ctx)

	// Create the table.
	fdTable := new(FDTable)
	fdTable.init()

	// Run the test.
	fn(ctx, fdTable, fd, limitSet)
}

// TestFDTableMany allocates maxFD FDs, i.e. maxes out the FDTable, until there
// is no room, then makes sure that NewFDAt works and also that if we remove
// one and add one that works too.
func TestFDTableMany(t *testing.T) {
	runTest(t, func(ctx context.Context, fdTable *FDTable, fd *vfs.FileDescription, _ *limits.LimitSet) {
		for i := 0; i < maxFD; i++ {
			if _, err := fdTable.NewFDs(ctx, 0, []*vfs.FileDescription{fd}, FDFlags{}); err != nil {
				t.Fatalf("Allocated %v FDs but wanted to allocate %v", i, maxFD)
			}
		}

		if _, err := fdTable.NewFDs(ctx, 0, []*vfs.FileDescription{fd}, FDFlags{}); err == nil {
			t.Fatalf("fdTable.NewFDs(0, r) in full map: got nil, wanted error")
		}

		if err := fdTable.NewFDAt(ctx, 1, fd, FDFlags{}); err != nil {
			t.Fatalf("fdTable.NewFDAt(1, r, FDFlags{}): got %v, wanted nil", err)
		}

		i := int32(2)
		fdTable.Remove(ctx, i)
		if fds, err := fdTable.NewFDs(ctx, 0, []*vfs.FileDescription{fd}, FDFlags{}); err != nil || fds[0] != i {
			t.Fatalf("Allocated %v FDs but wanted to allocate %v: %v", i, maxFD, err)
		}
	})
}

func TestFDTableOverLimit(t *testing.T) {
	runTest(t, func(ctx context.Context, fdTable *FDTable, fd *vfs.FileDescription, _ *limits.LimitSet) {
		if _, err := fdTable.NewFDs(ctx, maxFD, []*vfs.FileDescription{fd}, FDFlags{}); err == nil {
			t.Fatalf("fdTable.NewFDs(maxFD, f): got nil, wanted error")
		}

		if _, err := fdTable.NewFDs(ctx, maxFD-2, []*vfs.FileDescription{fd, fd, fd}, FDFlags{}); err == nil {
			t.Fatalf("fdTable.NewFDs(maxFD-2, {f,f,f}): got nil, wanted error")
		}

		if fds, err := fdTable.NewFDs(ctx, maxFD-3, []*vfs.FileDescription{fd, fd, fd}, FDFlags{}); err != nil {
			t.Fatalf("fdTable.NewFDs(maxFD-3, {f,f,f}): got %v, wanted nil", err)
		} else {
			for _, fd := range fds {
				fdTable.Remove(ctx, fd)
			}
		}

		if fds, err := fdTable.NewFDs(ctx, maxFD-1, []*vfs.FileDescription{fd}, FDFlags{}); err != nil || fds[0] != maxFD-1 {
			t.Fatalf("fdTable.NewFDAt(1, r, FDFlags{}): got %v, wanted nil", err)
		}

		if fds, err := fdTable.NewFDs(ctx, 0, []*vfs.FileDescription{fd}, FDFlags{}); err != nil {
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
	runTest(t, func(ctx context.Context, fdTable *FDTable, fd *vfs.FileDescription, limitSet *limits.LimitSet) {
		// Cap the limit at one.
		limitSet.Set(limits.NumberOfFiles, limits.Limit{1, maxFD}, true)

		if _, err := fdTable.NewFDs(ctx, 0, []*vfs.FileDescription{fd}, FDFlags{}); err != nil {
			t.Fatalf("Adding an FD to an empty 1-size map: got %v, want nil", err)
		}

		if _, err := fdTable.NewFDs(ctx, 0, []*vfs.FileDescription{fd}, FDFlags{}); err == nil {
			t.Fatalf("Adding an FD to a filled 1-size map: got nil, wanted an error")
		}

		// Remove the previous limit.
		limitSet.Set(limits.NumberOfFiles, limits.Limit{maxFD, maxFD}, true)

		if fds, err := fdTable.NewFDs(ctx, 0, []*vfs.FileDescription{fd}, FDFlags{}); err != nil {
			t.Fatalf("Adding an FD to a resized map: got %v, want nil", err)
		} else if len(fds) != 1 || fds[0] != 1 {
			t.Fatalf("Added an FD to a resized map: got %v, want {1}", fds)
		}

		if err := fdTable.NewFDAt(ctx, 1, fd, FDFlags{}); err != nil {
			t.Fatalf("Replacing FD 1 via fdTable.NewFDAt(1, r, FDFlags{}): got %v, wanted nil", err)
		}

		if err := fdTable.NewFDAt(ctx, maxFD+1, fd, FDFlags{}); err == nil {
			t.Fatalf("Using an FD that was too large via fdTable.NewFDAt(%v, r, FDFlags{}): got nil, wanted an error", maxFD+1)
		}

		if ref, _ := fdTable.Get(1); ref == nil {
			t.Fatalf("fdTable.Get(1): got nil, wanted %v", fd)
		}

		if ref, _ := fdTable.Get(2); ref != nil {
			t.Fatalf("fdTable.Get(2): got a %v, wanted nil", ref)
		}

		ref := fdTable.Remove(ctx, 1)
		if ref == nil {
			t.Fatalf("fdTable.Remove(1) for an existing FD: failed, want success")
		}
		ref.DecRef(ctx)

		if ref := fdTable.Remove(ctx, 1); ref != nil {
			t.Fatalf("r.Remove(1) for a removed FD: got success, want failure")
		}
	})
}

func TestDescriptorFlags(t *testing.T) {
	runTest(t, func(ctx context.Context, fdTable *FDTable, fd *vfs.FileDescription, _ *limits.LimitSet) {
		if err := fdTable.NewFDAt(ctx, 2, fd, FDFlags{CloseOnExec: true}); err != nil {
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

	runTest(b, func(ctx context.Context, fdTable *FDTable, fd *vfs.FileDescription, _ *limits.LimitSet) {
		fds, err := fdTable.NewFDs(ctx, 0, []*vfs.FileDescription{fd, fd, fd, fd, fd}, FDFlags{})
		if err != nil {
			b.Fatalf("fdTable.NewFDs: got %v, wanted nil", err)
		}

		b.StartTimer() // Benchmark.
		for i := 0; i < b.N; i++ {
			tf, _ := fdTable.Get(fds[i%len(fds)])
			tf.DecRef(ctx)
		}
	})
}

func BenchmarkFDLookupAndDecRefConcurrent(b *testing.B) {
	b.StopTimer() // Setup.

	runTest(b, func(ctx context.Context, fdTable *FDTable, fd *vfs.FileDescription, _ *limits.LimitSet) {
		fds, err := fdTable.NewFDs(ctx, 0, []*vfs.FileDescription{fd, fd, fd, fd, fd}, FDFlags{})
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
					tf.DecRef(ctx)
				}
			}()
		}
		wg.Wait()
	})
}

func TestSetFlagsForRange(t *testing.T) {
	type testCase struct {
		name    string
		startFd int32
		endFd   int32
		wantErr bool
	}
	testCases := []testCase{
		{"negative ranges", -100, -10, true},
		{"inverted positive ranges", 100, 10, true},
		{"good range", maxFD / 4, maxFD / 2, false},
	}

	for _, test := range testCases {
		runTest(t, func(ctx context.Context, fdTable *FDTable, fd *vfs.FileDescription, _ *limits.LimitSet) {
			for i := 0; i < maxFD; i++ {
				if _, err := fdTable.NewFDs(ctx, 0, []*vfs.FileDescription{fd}, FDFlags{}); err != nil {
					t.Fatalf("testCase: %v\nfdTable.NewFDs(_, 0, %+v, FDFlags{}): %d, want: nil", test, []*vfs.FileDescription{fd}, err)
				}
			}

			newFlags := FDFlags{CloseOnExec: true}
			if err := fdTable.SetFlagsForRange(ctx, test.startFd, test.endFd, newFlags); (err == nil) == test.wantErr {
				t.Fatalf("testCase: %v\nfdTable.SetFlagsForRange(_, %d, %d, %v): %v, waf: %t", test, test.startFd, test.endFd, newFlags, err, test.wantErr)
			}

			if test.wantErr {
				return
			}

			testRangeFlags := func(start int32, end int32, expected FDFlags) {
				for i := start; i <= end; i++ {
					file, flags := fdTable.Get(i)
					if file == nil || flags != expected {
						t.Fatalf("testCase: %v\nfdTable.Get(%d): (%v, %v), wanted (non-nil, %v)", test, i, file, flags, expected)
					}
				}
			}
			testRangeFlags(0, test.startFd-1, FDFlags{})
			testRangeFlags(test.startFd, test.endFd, newFlags)
			testRangeFlags(test.endFd+1, maxFD-1, FDFlags{})
		})
	}
}
