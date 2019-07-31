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

// Package common executes functions for proctor binaries.
package common

import (
	"flag"
	"fmt"
	"os"
)

var (
	list    = flag.Bool("list", false, "list all available tests")
	test    = flag.String("test", "", "run a single test from the list of available tests")
	version = flag.Bool("v", false, "print out the version of node that is installed")
)

// TestRunner is an interface to be implemented in each proctor binary.
type TestRunner interface {
	// ListTests returns a string slice of tests available to run.
	ListTests() ([]string, error)

	// RunTest runs a single test.
	RunTest(test string) error
}

// LaunchFunc parses flags passed by a proctor binary and calls the requested behavior.
func LaunchFunc(tr TestRunner) error {
	flag.Parse()

	if *list && *test != "" {
		flag.PrintDefaults()
		return fmt.Errorf("cannot specify 'list' and 'test' flags simultaneously")
	}
	if *list {
		tests, err := tr.ListTests()
		if err != nil {
			return fmt.Errorf("failed to list tests: %v", err)
		}
		for _, test := range tests {
			fmt.Println(test)
		}
		return nil
	}
	if *version {
		fmt.Println(os.Getenv("LANG_NAME"), "version:", os.Getenv("LANG_VER"), "is installed.")
		return nil
	}
	if *test != "" {
		if err := tr.RunTest(*test); err != nil {
			return fmt.Errorf("test %q failed to run: %v", *test, err)
		}
		return nil
	}

	if err := runAllTests(tr); err != nil {
		return fmt.Errorf("error running all tests: %v", err)
	}
	return nil
}

func runAllTests(tr TestRunner) error {
	tests, err := tr.ListTests()
	if err != nil {
		return fmt.Errorf("failed to list tests: %v", err)
	}
	for _, test := range tests {
		if err := tr.RunTest(test); err != nil {
			return fmt.Errorf("test %q failed to run: %v", test, err)
		}
	}
	return nil
}
