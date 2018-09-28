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
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/sentry/control"
	"gvisor.googlesource.com/gvisor/runsc/boot"
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

func startContainers(conf *boot.Config, specs []*specs.Spec, ids []string) ([]*Container, func(), error) {
	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		return nil, nil, fmt.Errorf("error creating root dir: %v", err)
	}

	var containers []*Container
	var bundles []string
	cleanup := func() {
		for _, c := range containers {
			c.Destroy()
		}
		for _, b := range bundles {
			os.RemoveAll(b)
		}
		os.RemoveAll(rootDir)
	}
	for i, spec := range specs {
		bundleDir, err := testutil.SetupContainerInRoot(rootDir, spec, conf)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("error setting up container: %v", err)
		}
		bundles = append(bundles, bundleDir)

		cont, err := Create(ids[i], spec, conf, bundleDir, "", "")
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("error creating container: %v", err)
		}
		containers = append(containers, cont)

		if err := cont.Start(conf); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("error starting container: %v", err)
		}
	}
	return containers, cleanup, nil
}

// TestMultiContainerSanity checks that it is possible to run 2 dead-simple
// containers in the same sandbox.
func TestMultiContainerSanity(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		// Setup the containers.
		sleep := []string{"sleep", "100"}
		specs, ids := createSpecs(sleep, sleep)
		containers, cleanup, err := startContainers(conf, specs, ids)
		if err != nil {
			t.Fatalf("error starting containers: %v", err)
		}
		defer cleanup()

		// Check via ps that multiple processes are running.
		expectedPL := []*control.Process{
			{PID: 1, Cmd: "sleep"},
		}
		if err := waitForProcessList(containers[0], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}
		expectedPL = []*control.Process{
			{PID: 2, Cmd: "sleep"},
		}
		if err := waitForProcessList(containers[1], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}
	}
}

func TestMultiContainerWait(t *testing.T) {
	// The first container should run the entire duration of the test.
	cmd1 := []string{"sleep", "100"}
	// We'll wait on the second container, which is much shorter lived.
	cmd2 := []string{"sleep", "1"}
	specs, ids := createSpecs(cmd1, cmd2)

	conf := testutil.TestConfig()
	containers, cleanup, err := startContainers(conf, specs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	// Check via ps that multiple processes are running.
	expectedPL := []*control.Process{
		{PID: 2, Cmd: "sleep"},
	}
	if err := waitForProcessList(containers[1], expectedPL); err != nil {
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
			if _, err := c.Wait(); err != nil {
				t.Errorf("wait for stopped container %s shouldn't fail: %v", c.Spec.Process.Args, err)
			}
		}(containers[1])
	}

	// Also wait via PID.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(c *Container) {
			defer wg.Done()
			const pid = 2
			if ws, err := c.WaitPID(pid, true /* clearStatus */); err != nil {
				t.Errorf("failed to wait for PID %d: %v", pid, err)
			} else if es := ws.ExitStatus(); es != 0 {
				t.Errorf("PID %d exited with non-zero status %d", pid, es)
			}
			if _, err := c.WaitPID(pid, true /* clearStatus */); err == nil {
				t.Errorf("wait for stopped PID %d should fail", pid)
			}
		}(containers[1])
	}

	wg.Wait()

	// After Wait returns, ensure that the root container is running and
	// the child has finished.
	expectedPL = []*control.Process{
		{PID: 1, Cmd: "sleep"},
	}
	if err := waitForProcessList(containers[0], expectedPL); err != nil {
		t.Errorf("failed to wait for %q to start: %v", strings.Join(containers[0].Spec.Process.Args, " "), err)
	}
}

// TestExecWait ensures what we can wait containers and individual processes in the
// sandbox that have already exited.
func TestExecWait(t *testing.T) {
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
	conf := testutil.TestConfig()
	containers, cleanup, err := startContainers(conf, specs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	// Check via ps that process is running.
	expectedPL := []*control.Process{
		{PID: 2, Cmd: "sleep"},
	}
	if err := waitForProcessList(containers[1], expectedPL); err != nil {
		t.Fatalf("failed to wait for sleep to start: %v", err)
	}

	// Wait for the second container to finish.
	if err := waitForProcessCount(containers[1], 0); err != nil {
		t.Fatalf("failed to wait for second container to stop: %v", err)
	}

	// Get the second container exit status.
	if ws, err := containers[1].Wait(); err != nil {
		t.Fatalf("failed to wait for process %s: %v", containers[1].Spec.Process.Args, err)
	} else if es := ws.ExitStatus(); es != 0 {
		t.Fatalf("process %s exited with non-zero status %d", containers[1].Spec.Process.Args, es)
	}
	if _, err := containers[1].Wait(); err != nil {
		t.Fatalf("wait for stopped container %s shouldn't fail: %v", containers[1].Spec.Process.Args, err)
	}

	// Execute another process in the first container.
	args := &control.ExecArgs{
		Filename:         "/bin/sleep",
		Argv:             []string{"/bin/sleep", "1"},
		WorkingDirectory: "/",
		KUID:             0,
	}
	pid, err := containers[0].Execute(args)
	if err != nil {
		t.Fatalf("error executing: %v", err)
	}

	// Wait for the exec'd process to exit.
	expectedPL = []*control.Process{
		{PID: 1, Cmd: "sleep"},
	}
	if err := waitForProcessList(containers[0], expectedPL); err != nil {
		t.Fatalf("failed to wait for second container to stop: %v", err)
	}

	// Get the exit status from the exec'd process.
	if ws, err := containers[0].WaitPID(pid, true /* clearStatus */); err != nil {
		t.Fatalf("failed to wait for process %+v with pid %d: %v", args, pid, err)
	} else if es := ws.ExitStatus(); es != 0 {
		t.Fatalf("process %+v exited with non-zero status %d", args, es)
	}
	if _, err := containers[0].WaitPID(pid, true /* clearStatus */); err == nil {
		t.Fatalf("wait for stopped process %+v should fail", args)
	}
}

// TestMultiContainerMount tests that bind mounts can be used with multiple
// containers.
func TestMultiContainerMount(t *testing.T) {
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
	conf := testutil.TestConfig()
	containers, cleanup, err := startContainers(conf, sps, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

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

		// Setup the containers.
		sleep := []string{"sleep", "100"}
		specs, ids := createSpecs(sleep, sleep)
		containers, cleanup, err := startContainers(conf, specs, ids)
		if err != nil {
			t.Fatalf("error starting containers: %v", err)
		}
		defer cleanup()

		// Check via ps that container 1 process is running.
		expectedPL := []*control.Process{
			{PID: 2, Cmd: "sleep"},
		}

		if err := waitForProcessList(containers[1], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}

		// Kill process 2.
		if err := containers[1].Signal(syscall.SIGKILL, false); err != nil {
			t.Errorf("failed to kill process 2: %v", err)
		}

		// Make sure process 1 is still running.
		expectedPL = []*control.Process{
			{PID: 1, Cmd: "sleep"},
		}
		if err := waitForProcessList(containers[0], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}

		// goferPid is reset when container is destroyed.
		goferPid := containers[1].GoferPid

		// Destroy container and ensure container's gofer process has exited.
		if err := containers[1].Destroy(); err != nil {
			t.Errorf("failed to destroy container: %v", err)
		}
		_, _, err = testutil.RetryEintr(func() (uintptr, uintptr, error) {
			cpid, err := syscall.Wait4(goferPid, nil, 0, nil)
			return uintptr(cpid), 0, err
		})
		if err != nil && err != syscall.ECHILD {
			t.Errorf("error waiting for gofer to exit: %v", err)
		}
		// Make sure process 1 is still running.
		if err := waitForProcessList(containers[0], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}

		// Now that process 2 is gone, ensure we get an error trying to
		// signal it again.
		if err := containers[1].Signal(syscall.SIGKILL, false); err == nil {
			t.Errorf("container %q shouldn't exist, but we were able to signal it", containers[1].ID)
		}

		// Kill process 1.
		if err := containers[0].Signal(syscall.SIGKILL, false); err != nil {
			t.Errorf("failed to kill process 1: %v", err)
		}

		// Ensure that container's gofer and sandbox process are no more.
		_, _, err = testutil.RetryEintr(func() (uintptr, uintptr, error) {
			cpid, err := syscall.Wait4(containers[0].GoferPid, nil, 0, nil)
			return uintptr(cpid), 0, err
		})
		if err != nil && err != syscall.ECHILD {
			t.Errorf("error waiting for gofer to exit: %v", err)
		}

		_, _, err = testutil.RetryEintr(func() (uintptr, uintptr, error) {
			cpid, err := syscall.Wait4(containers[0].Sandbox.Pid, nil, 0, nil)
			return uintptr(cpid), 0, err
		})
		if err != nil && err != syscall.ECHILD {
			t.Errorf("error waiting for sandbox to exit: %v", err)
		}

		// The sentry should be gone, so signaling should yield an error.
		if err := containers[0].Signal(syscall.SIGKILL, false); err == nil {
			t.Errorf("sandbox %q shouldn't exist, but we were able to signal it", containers[0].Sandbox.ID)
		}
	}
}

// TestMultiContainerDestroy checks that container are properly cleaned-up when
// they are destroyed.
func TestMultiContainerDestroy(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		// Two containers that will run for a long time. We will
		// destroy the second one.
		specs, ids := createSpecs([]string{"sleep", "100"}, []string{"sleep", "100"})
		containers, cleanup, err := startContainers(conf, specs, ids)
		if err != nil {
			t.Fatalf("error starting containers: %v", err)
		}
		defer cleanup()

		// Exec in the root container to check for the existence of the
		// second containers root filesystem directory.
		contDir := path.Join(boot.ChildContainersDir, containers[1].ID)
		args := &control.ExecArgs{
			Filename: "/usr/bin/test",
			Argv:     []string{"test", "-d", contDir},
		}
		if ws, err := containers[0].executeSync(args); err != nil {
			t.Fatalf("error executing %+v: %v", args, err)
		} else if ws.ExitStatus() != 0 {
			t.Errorf("exec 'test -f %q' got exit status %d, wanted 0", contDir, ws.ExitStatus())
		}

		// Destory the second container.
		if err := containers[1].Destroy(); err != nil {
			t.Fatalf("error destroying container: %v", err)
		}

		// Now the container dir should be gone.
		if ws, err := containers[0].executeSync(args); err != nil {
			t.Fatalf("error executing %+v: %v", args, err)
		} else if ws.ExitStatus() == 0 {
			t.Errorf("exec 'test -f %q' got exit status 0, wanted non-zero", contDir)
		}

		// Check that cont.Destroy is safe to call multiple times.
		if err := containers[1].Destroy(); err != nil {
			t.Errorf("error destroying container: %v", err)
		}
	}
}

func TestMultiContainerProcesses(t *testing.T) {
	// Note: use 'while true' to keep 'sh' process around. Otherwise, shell will
	// just execve into 'sleep' and both containers will look the same.
	specs, ids := createSpecs(
		[]string{"sleep", "100"},
		[]string{"sh", "-c", "while true; do sleep 100; done"})
	conf := testutil.TestConfig()
	containers, cleanup, err := startContainers(conf, specs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	// Check root's container process list doesn't include other containers.
	expectedPL0 := []*control.Process{
		{PID: 1, Cmd: "sleep"},
	}
	if err := waitForProcessList(containers[0], expectedPL0); err != nil {
		t.Errorf("failed to wait for process to start: %v", err)
	}

	// Same for the other container.
	expectedPL1 := []*control.Process{
		{PID: 2, Cmd: "sh"},
		{PID: 3, PPID: 2, Cmd: "sleep"},
	}
	if err := waitForProcessList(containers[1], expectedPL1); err != nil {
		t.Errorf("failed to wait for process to start: %v", err)
	}

	// Now exec into the second container and verify it shows up in the container.
	args := &control.ExecArgs{
		Filename: "/bin/sleep",
		Argv:     []string{"/bin/sleep", "100"},
	}
	if _, err := containers[1].Execute(args); err != nil {
		t.Fatalf("error exec'ing: %v", err)
	}
	expectedPL1 = append(expectedPL1, &control.Process{PID: 4, Cmd: "sleep"})
	if err := waitForProcessList(containers[1], expectedPL1); err != nil {
		t.Errorf("failed to wait for process to start: %v", err)
	}
	// Root container should remain unchanged.
	if err := waitForProcessList(containers[0], expectedPL0); err != nil {
		t.Errorf("failed to wait for process to start: %v", err)
	}
}

// TestMultiContainerKillAll checks that all process that belong to a container
// are killed when SIGKILL is sent to *all* processes in that container.
func TestMultiContainerKillAll(t *testing.T) {
	app, err := testutil.FindFile("runsc/container/test_app")
	if err != nil {
		t.Fatal("error finding test_app:", err)
	}

	// First container will remain intact while the second container is killed.
	specs, ids := createSpecs(
		[]string{app, "task-tree", "--depth=2", "--width=2"},
		[]string{app, "task-tree", "--depth=4", "--width=2"})
	conf := testutil.TestConfig()
	containers, cleanup, err := startContainers(conf, specs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	// Wait until all processes are created.
	rootProcCount := int(math.Pow(2, 3) - 1)
	if err := waitForProcessCount(containers[0], rootProcCount); err != nil {
		t.Fatal(err)
	}
	procCount := int(math.Pow(2, 5) - 1)
	if err := waitForProcessCount(containers[1], procCount); err != nil {
		t.Fatal(err)
	}

	// Exec more processes to ensure signal works for exec'd processes too.
	args := &control.ExecArgs{
		Filename: app,
		Argv:     []string{app, "task-tree", "--depth=2", "--width=2"},
	}
	if _, err := containers[1].Execute(args); err != nil {
		t.Fatalf("error exec'ing: %v", err)
	}
	procCount += 3
	if err := waitForProcessCount(containers[1], procCount); err != nil {
		t.Fatal(err)
	}

	// Kill'Em All
	containers[1].Signal(syscall.SIGKILL, true)

	// Check that all processes are gone.
	if err := waitForProcessCount(containers[1], 0); err != nil {
		t.Fatal(err)
	}
	// Check that root container was not affected.
	if err := waitForProcessCount(containers[0], rootProcCount); err != nil {
		t.Fatal(err)
	}
}
