// Copyright 2018 Google Inc.
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

package sandbox

import (
	"os"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
)

func init() {
	log.SetLevel(log.Debug)
	if err := testutil.ConfigureExePath(); err != nil {
		panic(err.Error())
	}
}

func TestGoferExits(t *testing.T) {
	spec := testutil.NewSpecWithArgs("/bin/sleep", "10000")
	rootDir, bundleDir, conf, err := testutil.SetupContainer(spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create, start and wait for the container.
	s, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer s.Destroy()
	if err := s.StartRoot(spec, conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	sandboxProc, err := os.FindProcess(s.Pid)
	if err != nil {
		t.Fatalf("error finding sandbox process: %v", err)
	}
	gofer, err := os.FindProcess(s.GoferPid)
	if err != nil {
		t.Fatalf("error finding sandbox process: %v", err)
	}

	// Kill sandbox and expect gofer to exit on its own.
	if err := sandboxProc.Kill(); err != nil {
		t.Fatalf("error killing sandbox process: %v", err)
	}
	if _, err := sandboxProc.Wait(); err != nil {
		t.Fatalf("error waiting for sandbox process: %v", err)
	}

	if _, err := gofer.Wait(); err != nil {
		t.Fatalf("error waiting for gofer process: %v", err)
	}
	if s.IsRunning() {
		t.Errorf("Sandbox shouldn't be running, sandbox: %+v", s)
	}
}
