// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package rubydev_test benchmarks Ruby CI/CD-type workloads.
package rubydev_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"gvisor.dev/gvisor/test/benchmarks/fs/fsbench"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

func runRubyBenchmark(b *testing.B, bm fsbench.FSBenchmark, cleanupDirPatterns []string) {
	b.Helper()
	ctx := context.Background()
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()
	bm.Image = "benchmarks/rubydev"
	cleanupDirPatterns = append(cleanupDirPatterns, "$HOME/.bundle/cache", "/tmp/rspec_failed_tests.txt")
	bm.CleanCmd = []string{"bash", "-c", fmt.Sprintf("rm -rf %s", strings.Join(cleanupDirPatterns, " "))}
	fsbench.RunWithDifferentFilesystems(ctx, b, machine, bm)
}

// BenchmarkRubyNoOpTest runs a no-op Ruby test.
// This is the test case that Stripe used to benchmark gVisor:
// https://stripe.com/blog/fast-secure-builds-choose-two
func BenchmarkRubyNoOpTest(b *testing.B) {
	runRubyBenchmark(b, fsbench.FSBenchmark{
		Image:      "benchmarks/rubydev",
		WorkDir:    "/files",
		RunCmd:     []string{"ruby", "tc_no_op.rb"},
		WantOutput: "100% passed",
	}, nil)
}

// BenchmarkRubySpecTest runs a complex test suite from the Fastlane project:
// https://github.com/fastlane/fastlane
func BenchmarkRubySpecTest(b *testing.B) {
	runRubyBenchmark(b, fsbench.FSBenchmark{
		Image:      "benchmarks/rubydev",
		WorkDir:    "/fastlane",
		RunCmd:     []string{"bash", "/files/run_fastlane_tests.sh"},
		WantOutput: "3613 examples, 0 failures",
	}, []string{
		// Fastlane tests pollute the filesystem a lot.
		// To find out, run `find / -exec stat  -c "%n %y" {} \; | sort` before and after running tests
		// for the first time, and diff them.
		"$HOME/Library", // Yes, even on Linux.
		"$HOME/.fastlane",
		"/tmp/fastlane*",
		"/tmp/spaceship*",
		"/tmp/profile_download*",
		"/tmp/d*-*-*/*.mobileprovision",
	})
}

// TestMain is the main method for this package.
func TestMain(m *testing.M) {
	harness.Init()
	harness.SetFixedBenchmarks()
	os.Exit(m.Run())
}
