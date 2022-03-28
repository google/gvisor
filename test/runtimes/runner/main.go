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

// Binary runner runs the runtime tests in a Docker container.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"gvisor.dev/gvisor/test/runtimes/runner/lib"
)

var (
	lang        = flag.String("lang", "", "language runtime to test")
	image       = flag.String("image", "", "docker image with runtime tests")
	excludeFile = flag.String("exclude_file", "", "file containing list of tests to exclude, in CSV format with fields: test name, bug id, comment")
	batchSize   = flag.Int("batch", 50, "number of test cases run in one command")
	timeout     = flag.Duration("timeout", 18*time.Minute, "batch timeout")
)

func main() {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
			return
		case <-time.After(time.Minute * 20):
			panic("timed out!!!")
		}
	}()
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(time.Minute):
				fmt.Fprintf(os.Stderr, "runner checking in %s\n", time.Now().String())
			}
		}
	}()
	flag.Parse()
	if *lang == "" || *image == "" {
		fmt.Fprintf(os.Stderr, "lang and image flags must not be empty\n")
		os.Exit(1)
	}
	os.Exit(lib.RunTests(*lang, *image, *excludeFile, *batchSize, *timeout))
}
