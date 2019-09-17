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
	"os/exec"
	"path/filepath"
	"regexp"
)

var nodejsTestRegEx = regexp.MustCompile(`^test-[^-].+\.js$`)

// Location of nodejs tests relative to working dir.
const nodejsTestDir = "test"

// nodejsRunner implements TestRunner for NodeJS.
type nodejsRunner struct{}

var _ TestRunner = nodejsRunner{}

// ListTests implements TestRunner.ListTests.
func (nodejsRunner) ListTests() ([]string, error) {
	testSlice, err := search(nodejsTestDir, nodejsTestRegEx)
	if err != nil {
		return nil, err
	}
	return testSlice, nil
}

// TestCmd implements TestRunner.TestCmd.
func (nodejsRunner) TestCmd(test string) *exec.Cmd {
	args := []string{filepath.Join("tools", "test.py"), test}
	return exec.Command("/usr/bin/python", args...)
}
