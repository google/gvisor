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

package container

import (
	"os"
	"strings"
	"sync"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/control"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
)

// TestMultiContainerSanity checks that it is possible to run 2 dead-simple
// containers in the same sandbox.
func TestMultiContainerSanity(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		containerIDs := []string{
			testutil.UniqueContainerID(),
			testutil.UniqueContainerID(),
		}
		containerAnnotations := []map[string]string{
			// The first container creates a sandbox.
			map[string]string{
				specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeSandbox,
			},
			// The second container creates a container within the first
			// container's sandbox.
			map[string]string{
				specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeContainer,
				specutils.ContainerdSandboxIDAnnotation:     containerIDs[0],
			},
		}

		rootDir, err := testutil.SetupRootDir()
		if err != nil {
			t.Fatalf("error creating root dir: %v", err)
		}
		defer os.RemoveAll(rootDir)

		// Setup the containers.
		containers := make([]*Container, 0, len(containerIDs))
		for i, annotations := range containerAnnotations {
			spec := testutil.NewSpecWithArgs("sleep", "100")
			spec.Annotations = annotations
			bundleDir, err := testutil.SetupContainerInRoot(rootDir, spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer os.RemoveAll(bundleDir)
			cont, err := Create(containerIDs[i], spec, conf, bundleDir, "", "")
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer cont.Destroy()
			if err := cont.Start(conf); err != nil {
				t.Fatalf("error starting container: %v", err)
			}
			containers = append(containers, cont)
		}

		expectedPL := []*control.Process{
			{
				UID:  0,
				PID:  1,
				PPID: 0,
				C:    0,
				Cmd:  "sleep",
			},
			{
				UID:  0,
				PID:  2,
				PPID: 0,
				C:    0,
				Cmd:  "sleep",
			},
		}

		// Check via ps that multiple processes are running.
		if err := waitForProcessList(containers[0], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}
	}
}

func TestMultiContainerWait(t *testing.T) {
	t.Skip("Test is flakey.") // TODO: Remove.
	containerIDs := []string{
		testutil.UniqueContainerID(),
		testutil.UniqueContainerID(),
	}
	containerAnnotations := []map[string]string{
		// The first container creates a sandbox.
		map[string]string{
			specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeSandbox,
		},
		// The second container creates a container within the first
		// container's sandbox.
		map[string]string{
			specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeContainer,
			specutils.ContainerdSandboxIDAnnotation:     containerIDs[0],
		},
	}
	args := [][]string{
		// The first container should run the entire duration of the
		// test.
		{"sleep", "100"},
		// We'll wait on the second container, which is much shorter
		// lived.
		{"sleep", "1"},
	}

	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer os.RemoveAll(rootDir)

	// Setup the containers.
	containers := make([]*Container, 0, len(containerIDs))
	for i, annotations := range containerAnnotations {
		spec := testutil.NewSpecWithArgs(args[i][0], args[i][1])
		spec.Annotations = annotations
		conf := testutil.TestConfig()
		bundleDir, err := testutil.SetupContainerInRoot(rootDir, spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(bundleDir)
		cont, err := Create(containerIDs[i], spec, conf, bundleDir, "", "")
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer cont.Destroy()
		if err := cont.Start(conf); err != nil {
			t.Fatalf("error starting container: %v", err)
		}
		containers = append(containers, cont)
	}

	expectedPL := []*control.Process{
		{
			UID:  0,
			PID:  1,
			PPID: 0,
			C:    0,
			Cmd:  "sleep",
		},
		{
			UID:  0,
			PID:  2,
			PPID: 0,
			C:    0,
			Cmd:  "sleep",
		},
	}

	// Check via ps that multiple processes are running.
	if err := waitForProcessList(containers[0], expectedPL); err != nil {
		t.Errorf("failed to wait for sleep to start: %v", err)
	}

	// Wait on the short lived container from multiple goroutines.
	wg := sync.WaitGroup{}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ws, err := containers[1].Wait(); err != nil {
				t.Errorf("failed to wait for process %q: %v", strings.Join(containers[1].Spec.Process.Args, " "), err)
			} else if es := ws.ExitStatus(); es != 0 {
				t.Errorf("process %q exited with non-zero status %d", strings.Join(containers[1].Spec.Process.Args, " "), es)
			}
			if _, err := containers[1].Wait(); err == nil {
				t.Errorf("wait for stopped process %q should fail", strings.Join(containers[1].Spec.Process.Args, " "))
			}

			// After Wait returns, ensure that the root container is running and
			// the child has finished.
			if err := waitForProcessList(containers[0], expectedPL[:1]); err != nil {
				t.Errorf("failed to wait for %q to start: %v", strings.Join(containers[0].Spec.Process.Args, " "), err)
			}
		}()
	}

	// Also wait via PID.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			const pid = 2
			if ws, err := containers[0].WaitPID(pid); err != nil {
				t.Errorf("failed to wait for PID %d: %v", pid, err)
			} else if es := ws.ExitStatus(); es != 0 {
				t.Errorf("PID %d exited with non-zero status %d", pid, es)
			}
			if _, err := containers[0].WaitPID(pid); err == nil {
				t.Errorf("wait for stopped PID %d should fail", pid)
			}
		}()
	}

	wg.Wait()
}
