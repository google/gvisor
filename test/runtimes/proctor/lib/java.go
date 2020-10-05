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

package lib

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Directories to exclude from tests.
var javaExclDirs = regexp.MustCompile(`(^(sun\/security)|(java\/util\/stream)|(java\/time)| )`)

// Location of java tests.
const javaTestDir = "/root/test/jdk"

// javaRunner implements TestRunner for Java.
type javaRunner struct{}

var _ TestRunner = javaRunner{}

// ListTests implements TestRunner.ListTests.
func (javaRunner) ListTests() ([]string, error) {
	args := []string{
		"-dir:" + javaTestDir,
		"-ignore:quiet",
		"-a",
		"-listtests",
		":jdk_core",
		":jdk_svc",
		":jdk_sound",
		":jdk_imageio",
	}
	cmd := exec.Command("jtreg", args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("jtreg -listtests : %v", err)
	}
	var testSlice []string
	for _, test := range strings.Split(string(out), "\n") {
		if !javaExclDirs.MatchString(test) {
			testSlice = append(testSlice, test)
		}
	}
	return testSlice, nil
}

// TestCmds implements TestRunner.TestCmds.
func (javaRunner) TestCmds(tests []string) []*exec.Cmd {
	args := append(
		[]string{
			"-agentvm",            // Execute each action using a pool of reusable JVMs.
			"-dir:" + javaTestDir, // Base directory for test files and directories.
			"-noreport",           // Do not generate a final report.
			"-timeoutFactor:20",   // Extend the default timeout (2 min) of all tests by this factor.
			"-verbose:nopass",     // Verbose output but supress it for tests that passed.
		},
		tests...,
	)
	return []*exec.Cmd{exec.Command("jtreg", args...)}
}
