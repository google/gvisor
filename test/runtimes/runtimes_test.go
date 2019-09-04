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

package runtimes

import (
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/runsc/testutil"
)

// Wait time for each test to run.
const timeout = 180 * time.Second

// Helper function to execute the docker container associated with the
// language passed.  Captures the output of the list function and executes
// each test individually, supplying any errors recieved.
func testLang(t *testing.T, lang string) {
	t.Helper()

	img := "gcr.io/gvisor-presubmit/" + lang
	if err := testutil.Pull(img); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}

	c := testutil.MakeDocker("gvisor-list")

	list, err := c.RunFg(img, "--list")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	c.CleanUp()

	tests := strings.Fields(list)

	for _, tc := range tests {
		tc := tc
		t.Run(tc, func(t *testing.T) {
			d := testutil.MakeDocker("gvisor-test")
			if err := d.Run(img, "--test", tc); err != nil {
				t.Fatalf("docker test %q failed to run: %v", tc, err)
			}
			defer d.CleanUp()

			status, err := d.Wait(timeout)
			if err != nil {
				t.Fatalf("docker test %q failed to wait: %v", tc, err)
			}
			if status == 0 {
				t.Logf("test %q passed", tc)
				return
			}
			logs, err := d.Logs()
			if err != nil {
				t.Fatalf("docker test %q failed to supply logs: %v", tc, err)
			}
			t.Errorf("test %q failed: %v", tc, logs)
		})
	}
}

func TestGo(t *testing.T) {
	testLang(t, "go")
}

func TestJava(t *testing.T) {
	testLang(t, "java")
}

func TestNodejs(t *testing.T) {
	testLang(t, "nodejs")
}

func TestPhp(t *testing.T) {
	testLang(t, "php")
}

func TestPython(t *testing.T) {
	testLang(t, "python")
}
