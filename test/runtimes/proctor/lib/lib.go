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

// Package lib contains proctor functions.
package lib

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"
)

// TestRunner is an interface that must be implemented for each runtime
// integrated with proctor.
type TestRunner interface {
	// ListTests returns a string slice of tests available to run.
	ListTests() ([]string, error)

	// TestCmds returns a slice of *exec.Cmd that will run the given tests.
	// There is no correlation between the number of exec.Cmds returned and the
	// number of tests. It could return one command to run all tests or a few
	// commands that collectively run all.
	TestCmds(tests []string) []*exec.Cmd
}

// TestRunnerForRuntime returns a new TestRunner for the given runtime.
func TestRunnerForRuntime(runtime string) (TestRunner, error) {
	switch runtime {
	case "go":
		return goRunner{}, nil
	case "java":
		return javaRunner{}, nil
	case "nodejs":
		return nodejsRunner{}, nil
	case "php":
		return phpRunner{}, nil
	case "python":
		return pythonRunner{}, nil
	}
	return nil, fmt.Errorf("invalid runtime %q", runtime)
}

// PauseAndReap is like init. It runs forever and reaps any children.
func PauseAndReap() {
	// Get notified of any new children.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGCHLD)

	for {
		if _, ok := <-ch; !ok {
			// Channel closed. This should not happen.
			panic("signal channel closed")
		}

		// Reap the child.
		for {
			if cpid, _ := unix.Wait4(-1, nil, unix.WNOHANG, nil); cpid < 1 {
				break
			}
		}
	}
}

// Search is a helper function to find tests in the given directory that match
// the regex.
func Search(root string, testFilter *regexp.Regexp) ([]string, error) {
	var testSlice []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		name := filepath.Base(path)

		if info.IsDir() || !testFilter.MatchString(name) {
			return nil
		}

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		testSlice = append(testSlice, relPath)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %q: %v", root, err)
	}

	return testSlice, nil
}
