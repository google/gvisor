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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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

// TestMultiContainerMount tests that bind mounts can be used with multiple
// containers.
func TestMultiContainerMount(t *testing.T) {
	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer os.RemoveAll(rootDir)

	cmd1 := []string{"sleep", "100"}

	// 'src != dst' ensures that 'dst' doesn't exist in the host and must be
	// properly mapped inside the container to work.
	src, err := ioutil.TempDir(testutil.TmpDir(), "container")
	if err != nil {
		t.Fatal("ioutil.TempDir failed:", err)
	}
	dst := src + ".dst"
	cmd2 := []string{"touch", filepath.Join(dst, "file")}

	sps, ids := createSpecs(cmd1, cmd2)
	sps[1].Mounts = append(sps[1].Mounts, specs.Mount{
		Source:      src,
		Destination: dst,
		Type:        "bind",
	})

	// Setup the containers.
	var containers []*Container
	for i, spec := range sps {
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

	ws, err := containers[1].Wait()
	if err != nil {
		t.Error("error waiting on container:", err)
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		t.Error("container failed, waitStatus:", ws)
	}
}

// TestMultiContainerSignal checks that it is possible to signal individual
// containers without killing the entire sandbox.
func TestMultiContainerSignal(t *testing.T) {
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

		// Kill process 2.
		if err := containers[1].Signal(syscall.SIGKILL); err != nil {
			t.Errorf("failed to kill process 2: %v", err)
		}

		// Make sure process 1 is still running.
		if err := waitForProcessList(containers[0], expectedPL[:1]); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}

		// Now that process 2 is gone, ensure we get an error trying to
		// signal it again.
		if err := containers[1].Signal(syscall.SIGKILL); err == nil {
			t.Errorf("container %q shouldn't exist, but we were able to signal it", containers[1].ID)
		}

		// Kill process 1.
		if err := containers[0].Signal(syscall.SIGKILL); err != nil {
			t.Errorf("failed to kill process 1: %v", err)
		}

		if err := waitForSandboxExit(containers[0]); err != nil {
			t.Errorf("failed to exit sandbox: %v", err)
		}

		// The sentry should be gone, so signaling should yield an
		// error.
		if err := containers[0].Signal(syscall.SIGKILL); err == nil {
			t.Errorf("sandbox %q shouldn't exist, but we were able to signal it", containers[0].Sandbox.ID)
		}
	}
}

// waitForSandboxExit waits until both the sandbox and gofer processes of the
// container have exited.
func waitForSandboxExit(container *Container) error {
	goferProc, _ := os.FindProcess(container.GoferPid)
	state, err := goferProc.Wait()
	if err != nil {
		return err
	}
	if !state.Exited() {
		return fmt.Errorf("gofer with PID %d failed to exit", container.GoferPid)
	}
	sandboxProc, _ := os.FindProcess(container.Sandbox.Pid)
	state, err = sandboxProc.Wait()
	if err != nil {
		return err
	}
	if !state.Exited() {
		return fmt.Errorf("sandbox with PID %d failed to exit", container.Sandbox.Pid)
	}
	return nil
}
