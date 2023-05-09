// Copyright 2019 The gVisor Authors.
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

// Binary runner runs the runtime tests in a Docker container.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/runtimes/runner/lib"
)

var (
	lang              = flag.String("lang", "", "language runtime to test")
	image             = flag.String("image", "", "docker image with runtime tests")
	excludeFile       = flag.String("exclude_file", "", "file containing list of tests to exclude, in CSV format with fields: test name, bug id, comment")
	onlyTests         = flag.String("tests", testutil.StringFromEnv("RUNTIME_TESTS_FILTER", ""), "if specified, runs only the given comma-separated list of test names, even those in --exclude_file")
	batchSize         = flag.Int("batch", 50, "number of test cases run in one command")
	timeout           = flag.Duration("timeout", 20*time.Minute, "batch timeout")
	perTestTimeout    = flag.Duration("per_test_timeout", testutil.DurationFromEnv("RUNTIME_TESTS_PER_TEST_TIMEOUT", 20*time.Minute), "per-test timeout (a value of 0 disables per-test timeouts)")
	runsPerTest       = flag.Int("runs_per_test", testutil.IntFromEnv("RUNTIME_TESTS_RUNS_PER_TEST", 1), "number of times to run each test (a value of 0 is the same as a value of 1, i.e. running once)")
	flakyIsError      = flag.Bool("flaky_is_error", testutil.BoolFromEnv("RUNTIME_TESTS_FLAKY_IS_ERROR", true), "if true, when running with multiple --runs_per_test, tests with inconsistent status will result in a failure status code for the batch; if false, they will be considered as passing")
	flakyShortCircuit = flag.Bool("flaky_short_circuit", testutil.BoolFromEnv("RUNTIME_TESTS_FLAKY_SHORT_CIRCUIT", true), "if true, when running with multiple --runs_per_test and a test is detected as flaky, exit immediately rather than running all --runs_per_test")
)

func main() {
	flag.Parse()
	if *lang == "" || *image == "" {
		fmt.Fprintf(os.Stderr, "lang and image flags must not be empty\n")
		os.Exit(1)
	}
	proctorSettings := lib.ProctorSettings{
		PerTestTimeout:    *perTestTimeout,
		RunsPerTest:       *runsPerTest,
		FlakyIsError:      *flakyIsError,
		FlakyShortCircuit: *flakyShortCircuit,
	}
	var filter lib.Filter
	if *excludeFile != "" {
		excludeFilter, err := lib.ExcludeFilter(*excludeFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting exclude list: %s\n", err.Error())
			os.Exit(1)
		}
		filter = excludeFilter
	}
	if *onlyTests != "" {
		tests := make(map[string]bool)
		for _, test := range strings.Split(*onlyTests, ",") {
			tests[test] = true
		}
		filter = func(test string) bool {
			return tests[test]
		}
	}
	os.Exit(lib.RunTests(*lang, *image, filter, *batchSize, *timeout, proctorSettings))
}
