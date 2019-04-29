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
	// ListTestFlag is the flag that will list tests in gtest binaries.
	ListTestFlag = "--gtest_list_tests"

	// FilterTestFlag is the flag that will filter tests in gtest binaries.
	FilterTestFlag = "--gtest_filter"
)

// TestCase is a single gtest test case.
type TestCase struct {
	// Suite is the suite for this test.
	Suite string

	// Name is the name of this individual test.
	Name string
}

// FullName returns the name of the test including the suite. It is suitable to
// pass to "-gtest_filter".
func (tc TestCase) FullName() string {
	return fmt.Sprintf("%s.%s", tc.Suite, tc.Name)
}

// ParseTestCases calls a gtest test binary to list its test and returns a
// slice with the name and suite of each test.
func ParseTestCases(testBin string, extraArgs ...string) ([]TestCase, error) {
	args := append([]string{ListTestFlag}, extraArgs...)
	cmd := exec.Command(testBin, args...)
	out, err := cmd.Output()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			return nil, fmt.Errorf("could not enumerate gtest tests: %v", err)
		}
		return nil, fmt.Errorf("could not enumerate gtest tests: %v\nstderr:\n%s", err, exitErr.Stderr)
	}

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

	if len(t) == 0 {
		return nil, fmt.Errorf("no tests parsed from %v", testBin)
	}
	return t, nil
}
