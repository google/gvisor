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

// Package gtest contains helpers for running google-test tests from Go.
package gtest

import (
	"fmt"
	"os/exec"
	"strings"
)

var (
	// listTestFlag is the flag that will list tests in gtest binaries.
	listTestFlag = "--gtest_list_tests"

	// filterTestFlag is the flag that will filter tests in gtest binaries.
	filterTestFlag = "--gtest_filter"

	// listBechmarkFlag is the flag that will list benchmarks in gtest binaries.
	listBenchmarkFlag = "--benchmark_list_tests"

	// filterBenchmarkFlag is the flag that will run specified benchmarks.
	filterBenchmarkFlag = "--benchmark_filter"
)

// TestCase is a single gtest test case.
type TestCase struct {
	// Suite is the suite for this test.
	Suite string

	// Name is the name of this individual test.
	Name string

	// all indicates that this will run without flags. This takes
	// precendence over benchmark below.
	all bool

	// benchmark indicates that this is a benchmark. In this case, the
	// suite will be empty, and we will use the appropriate test and
	// benchmark flags.
	benchmark bool
}

// FullName returns the name of the test including the suite. It is suitable to
// pass to "-gtest_filter".
func (tc TestCase) FullName() string {
	return fmt.Sprintf("%s.%s", tc.Suite, tc.Name)
}

// Args returns arguments to be passed when invoking the test.
func (tc TestCase) Args() []string {
	if tc.all {
		return []string{} // No arguments.
	}
	if tc.benchmark {
		return []string{
			fmt.Sprintf("%s=^%s$", filterBenchmarkFlag, tc.Name),
			fmt.Sprintf("%s=", filterTestFlag),
		}
	}
	return []string{
		fmt.Sprintf("%s=%s", filterTestFlag, tc.FullName()),
	}
}

// ParseTestCases calls a gtest test binary to list its test and returns a
// slice with the name and suite of each test.
//
// If benchmarks is true, then benchmarks will be included in the list of test
// cases provided. Note that this requires the binary to support the
// benchmarks_list_tests flag.
func ParseTestCases(testBin string, benchmarks bool, extraArgs ...string) ([]TestCase, error) {
	// Run to extract test cases.
	args := append([]string{listTestFlag}, extraArgs...)
	cmd := exec.Command(testBin, args...)
	out, err := cmd.Output()
	if err != nil {
		// We failed to list tests with the given flags. Just
		// return something that will run the binary with no
		// flags, which should execute all tests.
		return []TestCase{
			{
				Suite: "Default",
				Name:  "All",
				all:   true,
			},
		}, nil
	}

	// Parse test output.
	var t []TestCase
	var suite string
	for _, line := range strings.Split(string(out), "\n") {
		// Strip comments.
		line = strings.Split(line, "#")[0]

		// New suite?
		if !strings.HasPrefix(line, " ") {
			suite = strings.TrimSuffix(strings.TrimSpace(line), ".")
			continue
		}

		// Individual test.
		name := strings.TrimSpace(line)

		// Do we have a suite yet?
		if suite == "" {
			return nil, fmt.Errorf("test without a suite: %v", name)
		}

		// Add this individual test.
		t = append(t, TestCase{
			Suite: suite,
			Name:  name,
		})
	}

	// Finished?
	if !benchmarks {
		return t, nil
	}

	// Run again to extract benchmarks.
	args = append([]string{listBenchmarkFlag}, extraArgs...)
	cmd = exec.Command(testBin, args...)
	out, err = cmd.Output()
	if err != nil {
		// We were able to enumerate tests above, but not benchmarks?
		// We requested them, so we return an error in this case.
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			return nil, fmt.Errorf("could not enumerate gtest benchmarks: %v", err)
		}
		return nil, fmt.Errorf("could not enumerate gtest benchmarks: %v\nstderr\n%s", err, exitErr.Stderr)
	}

	benches := strings.Trim(string(out), "\n")
	if len(benches) == 0 {
		return t, nil
	}

	// Parse benchmark output.
	for _, line := range strings.Split(benches, "\n") {
		// Strip comments.
		line = strings.Split(line, "#")[0]

		// Single benchmark.
		name := strings.TrimSpace(line)

		// Add the single benchmark.
		t = append(t, TestCase{
			Suite:     "Benchmarks",
			Name:      name,
			benchmark: true,
		})
	}
	return t, nil
}
