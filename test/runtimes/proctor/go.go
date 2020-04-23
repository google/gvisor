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

package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var (
	goTestRegEx = regexp.MustCompile(`^.+\.go$`)

	// Directories with .dir contain helper files for tests.
	// Exclude benchmarks and stress tests.
	goDirFilter = regexp.MustCompile(`^(bench|stress)\/.+$|^.+\.dir.+$`)
)

// Location of Go tests on disk.
const goTestDir = "/usr/local/go/test"

// goRunner implements TestRunner for Go.
//
// There are two types of Go tests: "Go tool tests" and "Go tests on disk".
// "Go tool tests" are found and executed using `go tool dist test`. "Go tests
// on disk" are found in the /usr/local/go/test directory and are executed
// using `go run run.go`.
type goRunner struct{}

var _ TestRunner = goRunner{}

// ListTests implements TestRunner.ListTests.
func (goRunner) ListTests() ([]string, error) {
	// Go tool dist test tests.
	args := []string{"tool", "dist", "test", "-list"}
	cmd := exec.Command("go", args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list: %v", err)
	}
	var toolSlice []string
	for _, test := range strings.Split(string(out), "\n") {
		toolSlice = append(toolSlice, test)
	}

	// Go tests on disk.
	diskSlice, err := search(goTestDir, goTestRegEx)
	if err != nil {
		return nil, err
	}
	// Remove items from /bench/, /stress/ and .dir files
	diskFiltered := diskSlice[:0]
	for _, file := range diskSlice {
		if !goDirFilter.MatchString(file) {
			diskFiltered = append(diskFiltered, file)
		}
	}

	return append(toolSlice, diskFiltered...), nil
}

// TestCmd implements TestRunner.TestCmd.
func (goRunner) TestCmd(test string) *exec.Cmd {
	// Check if test exists on disk by searching for file of the same name.
	// This will determine whether or not it is a Go test on disk.
	if strings.HasSuffix(test, ".go") {
		// Test has suffix ".go" which indicates a disk test, run it as such.
		cmd := exec.Command("go", "run", "run.go", "-v", "--", test)
		cmd.Dir = goTestDir
		return cmd
	}

	// No ".go" suffix, run as a tool test.
	return exec.Command("go", "tool", "dist", "test", "-run", test)
}
