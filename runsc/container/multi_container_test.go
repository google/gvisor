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

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/sentry/control"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
)

func createSpecs(cmds ...[]string) ([]*specs.Spec, []string) {
	var specs []*specs.Spec
	var ids []string
	rootID := testutil.UniqueContainerID()

	for i, cmd := range cmds {
		spec := testutil.NewSpecWithArgs(cmd...)
		if i == 0 {
			spec.Annotations = map[string]string{
				specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeSandbox,
			}
			ids = append(ids, rootID)
		} else {
			spec.Annotations = map[string]string{
				specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeContainer,
				specutils.ContainerdSandboxIDAnnotation:     rootID,
			}
			ids = append(ids, testutil.UniqueContainerID())
		}
		specs = append(specs, spec)
	}
	return specs, ids
}

// TestMultiContainerSanity checks that it is possible to run 2 dead-simple
// containers in the same sandbox.
func TestMultiContainerSanity(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		rootDir, err := testutil.SetupRootDir()
		if err != nil {
			t.Fatalf("error creating root dir: %v", err)
		}
		defer os.RemoveAll(rootDir)

		// Setup the containers.
		sleep := []string{"sleep", "100"}
		specs, ids := createSpecs(sleep, sleep)
		var containers []*Container
		for i, spec := range specs {
			bundleDir, err := testutil.SetupContainerInRoot(rootDir, spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer os.RemoveAll(bundleDir)
			cont, err := Create(ids[i], spec, conf, bundleDir, "", "")
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer cont.Destroy()
			if err := cont.Start(conf); err != nil {
				t.Fatalf("error starting container: %v", err)
			}
			containers = append(containers, cont)
		}

		// Check via ps that multiple processes are running.
		expectedPL := []*control.Process{
			{PID: 1, Cmd: "sleep"},
			{PID: 2, Cmd: "sleep"},
		}
		if err := waitForProcessList(containers[0], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}
	}
}

func TestMultiContainerWait(t *testing.T) {
	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer os.RemoveAll(rootDir)

	// The first container should run the entire duration of the test.
	cmd1 := []string{"sleep", "100"}
	// We'll wait on the second container, which is much shorter lived.
	cmd2 := []string{"sleep", "1"}
	specs, ids := createSpecs(cmd1, cmd2)

	// Setup the containers.
	var containers []*Container
	for i, spec := range specs {
		conf := testutil.TestConfig()
		bundleDir, err := testutil.SetupContainerInRoot(rootDir, spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(bundleDir)
		cont, err := Create(ids[i], spec, conf, bundleDir, "", "")
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer cont.Destroy()
		if err := cont.Start(conf); err != nil {
			t.Fatalf("error starting container: %v", err)
		}
		containers = append(containers, cont)
	}

	// Check via ps that multiple processes are running.
	expectedPL := []*control.Process{
		{PID: 1, Cmd: "sleep"},
		{PID: 2, Cmd: "sleep"},
	}
	if err := waitForProcessList(containers[0], expectedPL); err != nil {
		t.Errorf("failed to wait for sleep to start: %v", err)
	}

	// Wait on the short lived container from multiple goroutines.
	wg := sync.WaitGroup{}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(c *Container) {
			defer wg.Done()
			if ws, err := c.Wait(); err != nil {
				t.Errorf("failed to wait for process %s: %v", c.Spec.Process.Args, err)
			} else if es := ws.ExitStatus(); es != 0 {
				t.Errorf("process %s exited with non-zero status %d", c.Spec.Process.Args, es)
			}
			if _, err := c.Wait(); err == nil {
				t.Errorf("wait for stopped process %s should fail", c.Spec.Process.Args)
			}
		}(containers[1])
	}

	// Also wait via PID.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(c *Container) {
			defer wg.Done()
			const pid = 2
			if ws, err := c.WaitPID(pid); err != nil {
				t.Errorf("failed to wait for PID %d: %v", pid, err)
			} else if es := ws.ExitStatus(); es != 0 {
				t.Errorf("PID %d exited with non-zero status %d", pid, es)
			}
			if _, err := c.WaitPID(pid); err == nil {
				t.Errorf("wait for stopped PID %d should fail", pid)
			}
			// TODO: use 'container[1]' when PID namespace is supported.
		}(containers[0])
	}

	wg.Wait()

	// After Wait returns, ensure that the root container is running and
	// the child has finished.
	if err := waitForProcessList(containers[0], expectedPL[:1]); err != nil {
		t.Errorf("failed to wait for %q to start: %v", strings.Join(containers[0].Spec.Process.Args, " "), err)
	}
}
