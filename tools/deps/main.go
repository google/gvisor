// Copyright 2026 The gVisor Authors.
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

// Command report prints the dependency violations found by a deps_test.
package main

import (
	"errors"
	"log"
	"os"
	"os/exec"
)

func main() {
	// Each test links to this binary and has its own adjacent report. Keep
	// the invoked name even when the test was found on a relative PATH.
	path, err := exec.LookPath(os.Args[0])
	if err != nil && !errors.Is(err, exec.ErrDot) {
		log.Fatal(err)
	}
	report, err := os.ReadFile(path + ".report")
	if err != nil {
		log.Fatal(err)
	}
	if len(report) != 0 {
		if _, err := os.Stdout.Write(report); err != nil {
			log.Fatal(err)
		}
		os.Exit(1)
	}
}
