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
	"log"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/runsc/dockerutil"
	"gvisor.dev/gvisor/runsc/testutil"
)

var (
	lang  = flag.String("lang", "", "language runtime to test")
	image = flag.String("image", "", "docker image with runtime tests")
)

// Wait time for each test to run.
const timeout = 5 * time.Minute

func main() {
	flag.Parse()
	if *lang == "" || *image == "" {
		fmt.Fprintf(os.Stderr, "lang and image flags must not be empty\n")
		os.Exit(1)
	}
	tests, err := testsForImage(*lang, *image)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}

	testing.Main(func(a, b string) (bool, error) {
		return a == b, nil
	}, tests, nil, nil)
}

func testsForImage(lang, image string) ([]testing.InternalTest, error) {
	if err := dockerutil.Pull(image); err != nil {
		return nil, fmt.Errorf("docker pull failed: %v", err)
	}

	c := dockerutil.MakeDocker("gvisor-list")
	list, err := c.RunFg(image, "--runtime", lang, "--list")
	defer c.CleanUp()
	if err != nil {
		return nil, fmt.Errorf("docker run failed: %v", err)
	}

	// Get subset of tests corresponding to shard.
	tests := strings.Fields(list)
	sort.Strings(tests)
	begin, end, err := testutil.TestBoundsForShard(len(tests))
	if err != nil {
		return nil, fmt.Errorf("TestsForShard() failed: %v", err)
	}
	log.Printf("Got bounds [%d:%d) for shard out of %d total tests", begin, end, len(tests))
	tests = tests[begin:end]

	var itests []testing.InternalTest
	for i, tc := range tests {
		// Capture tc in this scope.
		tc := tc
		itests = append(itests, testing.InternalTest{
			Name: tc,
			F: func(t *testing.T) {
				d := dockerutil.MakeDocker(fmt.Sprintf("gvisor-test-%d", i))
				defer d.CleanUp()
				if err := d.Run(image, "--runtime", lang, "--test", tc); err != nil {
					t.Fatalf("docker test %q failed to run: %v", tc, err)
				}

				status, err := d.Wait(timeout)
				if err != nil {
					t.Fatalf("docker test %q failed to wait: %v", tc, err)
				}
				logs, err := d.Logs()
				if err != nil {
					t.Fatalf("docker test %q failed to supply logs: %v", tc, err)
				}
				if status == 0 {
					t.Logf("test %q passed", tc)
					return
				}
				t.Errorf("test %q failed: %v", tc, logs)
			},
		})
	}
	return itests, nil
}
