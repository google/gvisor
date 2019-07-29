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

// Binary proctor-python is a utility that facilitates language testing for Pyhton.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)

var (
	list    = flag.Bool("list", false, "list all available tests")
	test    = flag.String("test", "", "run a single test from the list of available tests")
	version = flag.Bool("v", false, "print out the version of node that is installed")

	dir       = os.Getenv("LANG_DIR")
	testRegEx = regexp.MustCompile(`^test_.+\.py$`)
)

func main() {
	flag.Parse()

	if *list && *test != "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *list {
		tests, err := listTests()
		if err != nil {
			log.Fatalf("Failed to list tests: %v", err)
		}
		for _, test := range tests {
			fmt.Println(test)
		}
		return
	}
	if *version {
		fmt.Println("Python version: ", os.Getenv("LANG_VER"), " is installed.")
		return
	}
	if *test != "" {
		runTest(*test)
		return
	}
	runAllTests()
}

func listTests() ([]string, error) {
	var testSlice []string
	root := filepath.Join(dir, "Lib/test")

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		name := filepath.Base(path)

		if info.IsDir() || !testRegEx.MatchString(name) {
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

func runTest(test string) {
	args := []string{"-m", "test", test}
	cmd := exec.Command(filepath.Join(dir, "python"), args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to run: %v", err)
	}
}

func runAllTests() {
	tests, err := listTests()
	if err != nil {
		log.Fatalf("Failed to list tests: %v", err)
	}
	for _, test := range tests {
		runTest(test)
	}
}
