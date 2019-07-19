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

// Binary proctor-go is a utility that facilitates language testing for Go.

// There are two types of Go tests: "Go tool tests" and "Go tests on disk".
// "Go tool tests" are found and executed using `go tool dist test`.
// "Go tests on disk" are found in the /test directory and are
// executed using `go run run.go`.
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
	testDir   = filepath.Join(dir, "test")
	testRegEx = regexp.MustCompile(`^.+\.go$`)

	// Directories with .dir contain helper files for tests.
	// Exclude benchmarks and stress tests.
	exclDirs = regexp.MustCompile(`^.+\/(bench|stress)\/.+$|^.+\.dir.+$`)
)

func main() {
	flag.Parse()

	if *list && *test != "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *list {
		listTests()
		return
	}
	if *version {
		fmt.Println("Go version: ", os.Getenv("LANG_VER"), "  is installed.")
		return
	}
	runTest(*test)
}

func listTests() {
	// Go tool dist test tests.
	args := []string{"tool", "dist", "test", "-list"}
	cmd := exec.Command(filepath.Join(dir, "bin/go"), args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to list: %v", err)
	}

	// Go tests on disk.
	var tests []string
	if err := filepath.Walk(testDir, func(path string, info os.FileInfo, err error) error {
		name := filepath.Base(path)

		if info.IsDir() {
			return nil
		}

		if !testRegEx.MatchString(name) {
			return nil
		}

		if exclDirs.MatchString(path) {
			return nil
		}

		tests = append(tests, path)
		return nil
	}); err != nil {
		log.Fatalf("Failed to walk %q: %v", dir, err)
	}

	for _, file := range tests {
		fmt.Println(file)
	}
}

func runTest(test string) {
	toolArgs := []string{
		"tool",
		"dist",
		"test",
	}
	diskArgs := []string{
		"run",
		"run.go",
		"-v",
	}
	if test != "" {
		// Check if test exists on disk by searching for file of the same name.
		// This will determine whether or not it is a Go test on disk.
		if _, err := os.Stat(test); err == nil {
			relPath, err := filepath.Rel(testDir, test)
			if err != nil {
				log.Fatalf("Failed to get rel path: %v", err)
			}
			diskArgs = append(diskArgs, "--", relPath)
			cmd := exec.Command(filepath.Join(dir, "bin/go"), diskArgs...)
			cmd.Dir = testDir
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				log.Fatalf("Failed to run: %v", err)
			}
		} else if os.IsNotExist(err) {
			// File was not found, try running as Go tool test.
			toolArgs = append(toolArgs, "-run", test)
			cmd := exec.Command(filepath.Join(dir, "bin/go"), toolArgs...)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				log.Fatalf("Failed to run: %v", err)
			}
		} else {
			log.Fatalf("Error searching for test: %v", err)
		}
		return
	}
	runAllTool := exec.Command(filepath.Join(dir, "bin/go"), toolArgs...)
	runAllTool.Stdout, runAllTool.Stderr = os.Stdout, os.Stderr
	if err := runAllTool.Run(); err != nil {
		log.Fatalf("Failed to run: %v", err)
	}
	runAllDisk := exec.Command(filepath.Join(dir, "bin/go"), diskArgs...)
	runAllDisk.Dir = testDir
	runAllDisk.Stdout, runAllDisk.Stderr = os.Stdout, os.Stderr
	if err := runAllDisk.Run(); err != nil {
		log.Fatalf("Failed to run disk tests: %v", err)
	}
}
