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

package container_test

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/control"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/unet"
	"gvisor.googlesource.com/gvisor/runsc/container"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
)

func init() {
	log.SetLevel(log.Debug)
	if err := testutil.ConfigureExePath(); err != nil {
		panic(err.Error())
	}
}

// waitForProcessList waits for the given process list to show up in the container.
func waitForProcessList(s *container.Container, expected []*control.Process) error {
	var got []*control.Process
	for start := time.Now(); time.Now().Sub(start) < 10*time.Second; {
		var err error
		got, err = s.Processes()
		if err != nil {
			return fmt.Errorf("error getting process data from container: %v", err)
		}
		if procListsEqual(got, expected) {
			return nil
		}
		// Process might not have started, try again...
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("container got process list: %s, want: %s", procListToString(got), procListToString(expected))
}

// procListsEqual is used to check whether 2 Process lists are equal for all
// implemented fields.
func procListsEqual(got, want []*control.Process) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		pd1 := got[i]
		pd2 := want[i]
		// Zero out unimplemented and timing dependant fields.
		pd1.Time = ""
		pd1.STime = ""
		pd1.C = 0
		if *pd1 != *pd2 {
			return false
		}
	}
	return true
}

// getAndCheckProcLists is similar to waitForProcessList, but does not wait and retry the
// test for equality. This is because we already confirmed that exec occurred.
func getAndCheckProcLists(cont *container.Container, want []*control.Process) error {
	got, err := cont.Processes()
	if err != nil {
		return fmt.Errorf("error getting process data from container: %v", err)
	}
	if procListsEqual(got, want) {
		return nil
	}
	return fmt.Errorf("container got process list: %s, want: %s", procListToString(got), procListToString(want))
}

func procListToString(pl []*control.Process) string {
	strs := make([]string, 0, len(pl))
	for _, p := range pl {
		strs = append(strs, fmt.Sprintf("%+v", p))
	}
	return fmt.Sprintf("[%s]", strings.Join(strs, ","))
}

// createWriteableOutputFile creates an output file that can be read and written to in the sandbox.
func createWriteableOutputFile(path string) (*os.File, error) {
	outputFile, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0666)
	if err != nil {
		return nil, fmt.Errorf("error creating file: %q, %v", path, err)
	}

	// Chmod to allow writing after umask.
	if err := outputFile.Chmod(0666); err != nil {
		return nil, fmt.Errorf("error chmoding file: %q, %v", path, err)
	}
	return outputFile, nil
}

func readOutputNum(outputFile *os.File, path string, first bool) (int, error) {
	var num int
	time.Sleep(1 * time.Second)

	// Check that outputFile exists and contains counting data.
	fileInfo, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("error creating output file: %v", err)
	}

	if fileInfo.Size() == 0 {
		return 0, fmt.Errorf("failed to write to file, file still appears empty")
	}

	// Read the first number in the new file
	outputFileContent, err := ioutil.ReadAll(outputFile)
	if err != nil {
		return 0, fmt.Errorf("error reading file: %v", err)
	}
	if len(outputFileContent) == 0 {
		return 0, fmt.Errorf("error no content was read")
	}

	nums := strings.Split(string(outputFileContent), "\n")

	if first {
		num, err = strconv.Atoi(nums[0])
	} else {
		num, err = strconv.Atoi(nums[len(nums)-2])
	}
	if err != nil {
		return 0, fmt.Errorf("error getting number from file: %v", err)
	}
	return num, nil
}

// run starts the sandbox and waits for it to exit, checking that the
// application succeeded.
func run(spec *specs.Spec) error {
	rootDir, bundleDir, conf, err := testutil.SetupContainer(spec)
	if err != nil {
		return fmt.Errorf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create, start and wait for the container.
	s, err := container.Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "", "")
	if err != nil {
		return fmt.Errorf("error creating container: %v", err)
	}
	defer s.Destroy()
	if err := s.Start(conf); err != nil {
		return fmt.Errorf("error starting container: %v", err)
	}
	ws, err := s.Wait()
	if err != nil {
		return fmt.Errorf("error waiting on container: %v", err)
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		return fmt.Errorf("container failed, waitStatus: %v", ws)
	}
	return nil
}

// TestLifecycle tests the basic Create/Start/Signal/Destroy container lifecycle.
// It verifies after each step that the container can be loaded from disk, and
// has the correct status.
func TestLifecycle(t *testing.T) {
	// The container will just sleep for a long time.  We will kill it before
	// it finishes sleeping.
	spec := testutil.NewSpecWithArgs("sleep", "100")

	rootDir, bundleDir, conf, err := testutil.SetupContainer(spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// expectedPL lists the expected process state of the container.
	expectedPL := []*control.Process{
		{
			UID:  0,
			PID:  1,
			PPID: 0,
			C:    0,
			Cmd:  "sleep",
		},
	}
	// Create the container.
	id := testutil.UniqueContainerID()
	if _, err := container.Create(id, spec, conf, bundleDir, "", "", ""); err != nil {
		t.Fatalf("error creating container: %v", err)
	}

	// Load the container from disk and check the status.
	s, err := container.Load(rootDir, id)
	if err != nil {
		t.Fatalf("error loading container: %v", err)
	}
	if got, want := s.Status, container.Created; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}

	// List should return the container id.
	ids, err := container.List(rootDir)
	if err != nil {
		t.Fatalf("error listing containers: %v", err)
	}
	if got, want := ids, []string{id}; !reflect.DeepEqual(got, want) {
		t.Errorf("container list got %v, want %v", got, want)
	}

	// Start the container.
	if err := s.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}
	// Load the container from disk and check the status.
	s, err = container.Load(rootDir, id)
	if err != nil {
		t.Fatalf("error loading container: %v", err)
	}
	if got, want := s.Status, container.Running; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}

	// Verify that "sleep 100" is running.
	if err := waitForProcessList(s, expectedPL); err != nil {
		t.Error(err)
	}

	// Wait on the container.
	var wg sync.WaitGroup
	wg.Add(1)
	ch := make(chan struct{})
	go func() {
		ch <- struct{}{}
		ws, err := s.Wait()
		if err != nil {
			t.Fatalf("error waiting on container: %v", err)
		}
		if got, want := ws.Signal(), syscall.SIGTERM; got != want {
			t.Fatalf("got signal %v, want %v", got, want)
		}
		wg.Done()
	}()

	// Wait a bit to ensure that we've started waiting on the container
	// before we signal.
	<-ch
	time.Sleep(100 * time.Millisecond)
	// Send the container a SIGTERM which will cause it to stop.
	if err := s.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("error sending signal %v to container: %v", syscall.SIGTERM, err)
	}
	// Wait for it to die.
	wg.Wait()

	// The sandbox process should have exited by now, but it is a zombie.
	// In normal runsc usage, it will be parented to init, and init will
	// reap the sandbox. However, in this case the test runner is the
	// parent and will not reap the sandbox process, so we must do it
	// ourselves.
	p, _ := os.FindProcess(s.Sandbox.Pid)
	p.Wait()
	g, _ := os.FindProcess(s.Sandbox.GoferPid)
	g.Wait()

	// Load the container from disk and check the status.
	s, err = container.Load(rootDir, id)
	if err != nil {
		t.Fatalf("error loading container: %v", err)
	}
	if got, want := s.Status, container.Stopped; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}

	// Destroy the container.
	if err := s.Destroy(); err != nil {
		t.Fatalf("error destroying container: %v", err)
	}

	// List should not return the container id.
	ids, err = container.List(rootDir)
	if err != nil {
		t.Fatalf("error listing containers: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected container list to be empty, but got %v", ids)
	}

	// Loading the container by id should fail.
	if _, err = container.Load(rootDir, id); err == nil {
		t.Errorf("expected loading destroyed container to fail, but it did not")
	}
}

// Test the we can execute the application with different path formats.
func TestExePath(t *testing.T) {
	for _, test := range []struct {
		path    string
		success bool
	}{
		{path: "true", success: true},
		{path: "bin/true", success: true},
		{path: "/bin/true", success: true},
		{path: "thisfiledoesntexit", success: false},
		{path: "bin/thisfiledoesntexit", success: false},
		{path: "/bin/thisfiledoesntexit", success: false},
	} {
		spec := testutil.NewSpecWithArgs(test.path)
		rootDir, bundleDir, conf, err := testutil.SetupContainer(spec)
		if err != nil {
			t.Fatalf("exec: %s, error setting up container: %v", test.path, err)
		}

		ws, err := container.Run(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")

		os.RemoveAll(rootDir)
		os.RemoveAll(bundleDir)

		if test.success {
			if err != nil {
				t.Errorf("exec: %s, error running container: %v", test.path, err)
			}
			if ws.ExitStatus() != 0 {
				t.Errorf("exec: %s, got exit status %v want %v", test.path, ws.ExitStatus(), 0)
			}
		} else {
			if err == nil {
				t.Errorf("exec: %s, got: no error, want: error", test.path)
			}
		}
	}
}

// Test the we can retrieve the application exit status from the container.
func TestAppExitStatus(t *testing.T) {
	// First container will succeed.
	succSpec := testutil.NewSpecWithArgs("true")

	rootDir, bundleDir, conf, err := testutil.SetupContainer(succSpec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	ws, err := container.Run(testutil.UniqueContainerID(), succSpec, conf, bundleDir, "", "")
	if err != nil {
		t.Fatalf("error running container: %v", err)
	}
	if ws.ExitStatus() != 0 {
		t.Errorf("got exit status %v want %v", ws.ExitStatus(), 0)
	}

	// Second container exits with non-zero status.
	wantStatus := 123
	errSpec := testutil.NewSpecWithArgs("bash", "-c", fmt.Sprintf("exit %d", wantStatus))

	rootDir2, bundleDir2, conf, err := testutil.SetupContainer(errSpec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir2)
	defer os.RemoveAll(bundleDir2)

	ws, err = container.Run(testutil.UniqueContainerID(), succSpec, conf, bundleDir2, "", "")
	if err != nil {
		t.Fatalf("error running container: %v", err)
	}
	if ws.ExitStatus() != wantStatus {
		t.Errorf("got exit status %v want %v", ws.ExitStatus(), wantStatus)
	}
}

// TestExec verifies that a container can exec a new program.
func TestExec(t *testing.T) {
	const uid = 343
	spec := testutil.NewSpecWithArgs("sleep", "100")

	rootDir, bundleDir, conf, err := testutil.SetupContainer(spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create and start the container.
	s, err := container.Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "", "")
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer s.Destroy()
	if err := s.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// expectedPL lists the expected process state of the container.
	expectedPL := []*control.Process{
		{
			UID:  0,
			PID:  1,
			PPID: 0,
			C:    0,
			Cmd:  "sleep",
		},
		{
			UID:  uid,
			PID:  2,
			PPID: 0,
			C:    0,
			Cmd:  "sleep",
		},
	}

	// Verify that "sleep 100" is running.
	if err := waitForProcessList(s, expectedPL[:1]); err != nil {
		t.Error(err)
	}

	execArgs := control.ExecArgs{
		Filename:         "/bin/sleep",
		Argv:             []string{"sleep", "5"},
		Envv:             []string{"PATH=" + os.Getenv("PATH")},
		WorkingDirectory: "/",
		KUID:             uid,
	}

	// Verify that "sleep 100" and "sleep 5" are running after exec.
	// First, start running exec (whick blocks).
	status := make(chan error, 1)
	go func() {
		exitStatus, err := s.Execute(&execArgs)
		if err != nil {
			status <- err
		} else if exitStatus != 0 {
			status <- fmt.Errorf("failed with exit status: %v", exitStatus)
		} else {
			status <- nil
		}
	}()

	if err := waitForProcessList(s, expectedPL); err != nil {
		t.Fatal(err)
	}

	// Ensure that exec finished without error.
	select {
	case <-time.After(10 * time.Second):
		t.Fatalf("container timed out waiting for exec to finish.")
	case st := <-status:
		if st != nil {
			t.Errorf("container failed to exec %v: %v", execArgs, err)
		}
	}
}

// TestCheckpointRestore creates a container that continuously writes successive integers
// to a file. To test checkpoint and restore functionality, the container is
// checkpointed and the last number printed to the file is recorded. Then, it is restored in two
// new containers and the first number printed from these containers is checked. Both should
// be the next consecutive number after the last number from the checkpointed container.
func TestCheckpointRestore(t *testing.T) {
	outputPath := filepath.Join(os.TempDir(), "output")
	outputFile, err := createWriteableOutputFile(outputPath)
	if err != nil {
		t.Fatalf("error creating output file: %v", err)
	}
	defer outputFile.Close()

	outputFileSandbox := strings.Replace(outputPath, os.TempDir(), "/tmp2", -1)

	script := fmt.Sprintf("for ((i=0; ;i++)); do echo $i >> %s; sleep 1; done", outputFileSandbox)
	spec := testutil.NewSpecWithArgs("bash", "-c", script)
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Type:        "bind",
		Destination: "/tmp2",
		Source:      os.TempDir(),
	})

	rootDir, bundleDir, conf, err := testutil.SetupContainer(spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create and start the container.
	cont, err := container.Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "", "")
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// Set the image path, which is where the checkpoint image will be saved.
	imagePath := filepath.Join(os.TempDir(), "test-image-file")

	// Create the image file and open for writing.
	file, err := os.OpenFile(imagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("error opening new file at imagePath: %v", err)
	}
	defer file.Close()

	time.Sleep(1 * time.Second)

	// Checkpoint running container; save state into new file.
	if err := cont.Checkpoint(file); err != nil {
		t.Fatalf("error checkpointing container to empty file: %v", err)
	}
	defer os.RemoveAll(imagePath)

	lastNum, err := readOutputNum(outputFile, outputPath, false)
	if err != nil {
		t.Fatalf("error with outputFile: %v", err)
	}

	// Delete and recreate file before restoring.
	if err := os.Remove(outputPath); err != nil {
		t.Fatalf("error removing file")
	}
	outputFile2, err := createWriteableOutputFile(outputPath)
	if err != nil {
		t.Fatalf("error creating output file: %v", err)
	}
	defer outputFile2.Close()

	// Restore into a new container.
	cont2, err := container.Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "", imagePath)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont2.Destroy()
	if err := cont2.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	firstNum, err := readOutputNum(outputFile2, outputPath, true)
	if err != nil {
		t.Fatalf("error with outputFile: %v", err)
	}

	// Check that lastNum is one less than firstNum and that the container picks up from where it left off.
	if lastNum+1 != firstNum {
		t.Errorf("error numbers not in order, previous: %d, next: %d", lastNum, firstNum)
	}

	// Restore into another container!
	// Delete and recreate file before restoring.
	if err := os.Remove(outputPath); err != nil {
		t.Fatalf("error removing file")
	}
	outputFile3, err := createWriteableOutputFile(outputPath)
	if err != nil {
		t.Fatalf("error creating output file: %v", err)
	}
	defer outputFile3.Close()

	// Restore into a new container.
	cont3, err := container.Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "", imagePath)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont3.Destroy()
	if err := cont3.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	firstNum2, err := readOutputNum(outputFile3, outputPath, true)
	if err != nil {
		t.Fatalf("error with outputFile: %v", err)
	}

	// Check that lastNum is one less than firstNum and that the container picks up from where it left off.
	if lastNum+1 != firstNum2 {
		t.Errorf("error numbers not in order, previous: %d, next: %d", lastNum, firstNum)
	}

}

// TestPauseResume tests that we can successfully pause and resume a container.
// It checks starts running sleep and executes another sleep. It pauses and checks
// that both processes are still running: sleep will be paused and still exist.
// It will then unpause and confirm that both processes are running. Then it will
// wait until one sleep completes and check to make sure the other is running.
func TestPauseResume(t *testing.T) {
	const uid = 343
	spec := testutil.NewSpecWithArgs("sleep", "20")

	rootDir, bundleDir, conf, err := testutil.SetupContainer(spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create and start the container.
	cont, err := container.Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "", "")
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// expectedPL lists the expected process state of the container.
	expectedPL := []*control.Process{
		{
			UID:  0,
			PID:  1,
			PPID: 0,
			C:    0,
			Cmd:  "sleep",
		},
		{
			UID:  uid,
			PID:  2,
			PPID: 0,
			C:    0,
			Cmd:  "sleep",
		},
	}

	execArgs := control.ExecArgs{
		Filename:         "/bin/sleep",
		Argv:             []string{"sleep", "5"},
		Envv:             []string{"PATH=" + os.Getenv("PATH")},
		WorkingDirectory: "/",
		KUID:             uid,
	}

	// First, start running exec (whick blocks).
	go cont.Execute(&execArgs)

	// Verify that "sleep 5" is running.
	if err := waitForProcessList(cont, expectedPL); err != nil {
		t.Fatal(err)
	}

	// Pause the running container.
	if err := cont.Pause(); err != nil {
		t.Errorf("error pausing container: %v", err)
	}
	if got, want := cont.Status, container.Paused; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}

	time.Sleep(10 * time.Second)

	// Verify that the two processes still exist. Sleep 5 is paused so
	// it should still be in the process list after 10 seconds.
	if err := getAndCheckProcLists(cont, expectedPL); err != nil {
		t.Fatal(err)
	}

	// Resume the running container.
	if err := cont.Resume(); err != nil {
		t.Errorf("error pausing container: %v", err)
	}
	if got, want := cont.Status, container.Running; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}

	if err := getAndCheckProcLists(cont, expectedPL); err != nil {
		t.Fatal(err)
	}

	expectedPL2 := []*control.Process{
		{
			UID:  0,
			PID:  1,
			PPID: 0,
			C:    0,
			Cmd:  "sleep",
		},
	}

	// Verify there is only one process left since we waited 10 at most seconds for
	// sleep 5 to end.
	if err := waitForProcessList(cont, expectedPL2); err != nil {
		t.Fatal(err)
	}
}

// TestPauseResumeStatus makes sure that the statuses are set correctly
// with calls to pause and resume and that pausing and resuming only
// occurs given the correct state.
func TestPauseResumeStatus(t *testing.T) {
	spec := testutil.NewSpecWithArgs("sleep", "20")

	rootDir, bundleDir, conf, err := testutil.SetupContainer(spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create and start the container.
	cont, err := container.Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "", "")
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// Pause the running container.
	if err := cont.Pause(); err != nil {
		t.Errorf("error pausing container: %v", err)
	}
	if got, want := cont.Status, container.Paused; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}

	// Try to Pause again. Should cause error.
	if err := cont.Pause(); err == nil {
		t.Errorf("error pausing container that was already paused: %v", err)
	}
	if got, want := cont.Status, container.Paused; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}

	// Resume the running container.
	if err := cont.Resume(); err != nil {
		t.Errorf("error resuming container: %v", err)
	}
	if got, want := cont.Status, container.Running; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}

	// Try to resume again. Should cause error.
	if err := cont.Resume(); err == nil {
		t.Errorf("error resuming container already running: %v", err)
	}
	if got, want := cont.Status, container.Running; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}
}

// TestCapabilities verifies that:
// - Running exec as non-root UID and GID will result in an error (because the
//   executable file can't be read).
// - Running exec as non-root with CAP_DAC_OVERRIDE succeeds because it skips
//   this check.
func TestCapabilities(t *testing.T) {
	const uid = 343
	const gid = 2401
	spec := testutil.NewSpecWithArgs("sleep", "100")

	// We generate files in the host temporary directory.
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: os.TempDir(),
		Source:      os.TempDir(),
		Type:        "bind",
	})

	rootDir, bundleDir, conf, err := testutil.SetupContainer(spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create and start the container.
	s, err := container.Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "", "")
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer s.Destroy()
	if err := s.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// expectedPL lists the expected process state of the container.
	expectedPL := []*control.Process{
		{
			UID:  0,
			PID:  1,
			PPID: 0,
			C:    0,
			Cmd:  "sleep",
		},
		{
			UID:  uid,
			PID:  2,
			PPID: 0,
			C:    0,
			Cmd:  "exe",
		},
	}
	if err := waitForProcessList(s, expectedPL[:1]); err != nil {
		t.Fatalf("Failed to wait for sleep to start, err: %v", err)
	}

	// Create an executable that can't be run with the specified UID:GID.
	// This shouldn't be callable within the container until we add the
	// CAP_DAC_OVERRIDE capability to skip the access check.
	exePath := filepath.Join(rootDir, "exe")
	if err := ioutil.WriteFile(exePath, []byte("#!/bin/sh\necho hello"), 0770); err != nil {
		t.Fatalf("couldn't create executable: %v", err)
	}
	defer os.Remove(exePath)

	// Need to traverse the intermediate directory.
	os.Chmod(rootDir, 0755)

	execArgs := control.ExecArgs{
		Filename:         exePath,
		Argv:             []string{exePath},
		Envv:             []string{"PATH=" + os.Getenv("PATH")},
		WorkingDirectory: "/",
		KUID:             uid,
		KGID:             gid,
		Capabilities:     &auth.TaskCapabilities{},
	}

	// "exe" should fail because we don't have the necessary permissions.
	if _, err := s.Execute(&execArgs); err == nil {
		t.Fatalf("container executed without error, but an error was expected")
	}

	// Now we run with the capability enabled and should succeed.
	execArgs.Capabilities = &auth.TaskCapabilities{
		EffectiveCaps: auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
	}
	// "exe" should not fail this time.
	if _, err := s.Execute(&execArgs); err != nil {
		t.Fatalf("container failed to exec %v: %v", execArgs, err)
	}
}

// Test that an tty FD is sent over the console socket if one is provided.
func TestConsoleSocket(t *testing.T) {
	spec := testutil.NewSpecWithArgs("true")
	rootDir, bundleDir, conf, err := testutil.SetupContainer(spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create a named socket and start listening.  We use a relative path
	// to avoid overflowing the unix path length limit (108 chars).
	socketPath := filepath.Join(bundleDir, "socket")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("error getting cwd: %v", err)
	}
	socketRelPath, err := filepath.Rel(cwd, socketPath)
	if err != nil {
		t.Fatalf("error getting relative path for %q from cwd %q: %v", socketPath, cwd, err)
	}
	if len(socketRelPath) > len(socketPath) {
		socketRelPath = socketPath
	}
	srv, err := unet.BindAndListen(socketRelPath, false)
	if err != nil {
		t.Fatalf("error binding and listening to socket %q: %v", socketPath, err)
	}
	defer os.Remove(socketPath)

	// Create the container and pass the socket name.
	id := testutil.UniqueContainerID()
	s, err := container.Create(id, spec, conf, bundleDir, socketRelPath, "", "")
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}

	// Open the othe end of the socket.
	sock, err := srv.Accept()
	if err != nil {
		t.Fatalf("error accepting socket connection: %v", err)
	}

	// Allow 3 fds to be received.  We only expect 1.
	r := sock.Reader(true /* blocking */)
	r.EnableFDs(1)

	// The socket is closed right after sending the FD, so EOF is
	// an allowed error.
	b := [][]byte{{}}
	if _, err := r.ReadVec(b); err != nil && err != io.EOF {
		t.Fatalf("error reading from socket connection: %v", err)
	}

	// We should have gotten a control message.
	fds, err := r.ExtractFDs()
	if err != nil {
		t.Fatalf("error extracting fds from socket connection: %v", err)
	}
	if len(fds) != 1 {
		t.Fatalf("got %d fds from socket, wanted 1", len(fds))
	}

	// Verify that the fd is a terminal.
	if _, err := unix.IoctlGetTermios(fds[0], unix.TCGETS); err != nil {
		t.Errorf("fd is not a terminal (ioctl TGGETS got %v)", err)
	}

	// Shut it down.
	if err := s.Destroy(); err != nil {
		t.Fatalf("error destroying container: %v", err)
	}

	// Close socket.
	if err := srv.Close(); err != nil {
		t.Fatalf("error destroying container: %v", err)
	}
}

// TestRunNonRoot checks that sandbox can be configured when running as
// non-privileged user.
func TestRunNonRoot(t *testing.T) {
	spec := testutil.NewSpecWithArgs("/bin/true")
	spec.Process.User.UID = 343
	spec.Process.User.GID = 2401

	// User that container runs as can't list '$TMP/blocked' and would fail to
	// mount it.
	dir, err := ioutil.TempDir("", "blocked")
	if err != nil {
		t.Fatalf("ioutil.TempDir() failed: %v", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatalf("os.MkDir(%q) failed: %v", dir, err)
	}
	dir = path.Join(dir, "test")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatalf("os.MkDir(%q) failed: %v", dir, err)
	}

	// We generate files in the host temporary directory.
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: dir,
		Source:      dir,
		Type:        "bind",
	})

	if err := run(spec); err != nil {
		t.Fatalf("error running sadbox: %v", err)
	}
}

// TestMountNewDir checks that runsc will create destination directory if it
// doesn't exit.
func TestMountNewDir(t *testing.T) {
	srcDir := path.Join(os.TempDir(), "src", "newdir", "anotherdir")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("os.MkDir(%q) failed: %v", srcDir, err)
	}

	// Attempt to remove dir to ensure it doesn't exist.
	mountDir := path.Join(os.TempDir(), "newdir")
	if err := os.RemoveAll(mountDir); err != nil {
		t.Fatalf("os.RemoveAll(%q) failed: %v", mountDir, err)
	}
	mountDir = path.Join(mountDir, "anotherdir")

	spec := testutil.NewSpecWithArgs("/bin/ls", mountDir)
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: mountDir,
		Source:      srcDir,
		Type:        "bind",
	})

	if err := run(spec); err != nil {
		t.Fatalf("error running sadbox: %v", err)
	}
}

// TestAbbreviatedIDs checks that runsc supports using abbreviated container
// IDs in place of full IDs.
func TestAbbreviatedIDs(t *testing.T) {
	cids := []string{
		"foo-" + testutil.UniqueContainerID(),
		"bar-" + testutil.UniqueContainerID(),
		"baz-" + testutil.UniqueContainerID(),
	}

	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	for _, cid := range cids {
		spec := testutil.NewSpecWithArgs("sleep", "100")
		bundleDir, conf, err := testutil.SetupContainerInRoot(rootDir, spec)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		// Create and start the container.
		cont, err := container.Create(cid, spec, conf, bundleDir, "", "", "")
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer cont.Destroy()
	}

	// These should all be unambigious.
	unambiguous := map[string]string{
		"f":     cids[0],
		cids[0]: cids[0],
		"bar":   cids[1],
		cids[1]: cids[1],
		"baz":   cids[2],
		cids[2]: cids[2],
	}
	for shortid, longid := range unambiguous {
		if _, err := container.Load(rootDir, shortid); err != nil {
			t.Errorf("%q should resolve to %q: %v", shortid, longid, err)
		}
	}

	// These should be ambiguous.
	ambiguous := []string{
		"b",
		"ba",
	}
	for _, shortid := range ambiguous {
		if s, err := container.Load(rootDir, shortid); err == nil {
			t.Errorf("%q should be ambiguous, but resolved to %q", shortid, s.ID)
		}
	}
}

// TestMultiContainerSanity checks that it is possible to run 2 dead-simple
// containers in the same sandbox.
func TestMultiContainerSanity(t *testing.T) {
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
	containers := make([]*container.Container, 0, len(containerIDs))
	for i, annotations := range containerAnnotations {
		spec := testutil.NewSpecWithArgs("sleep", "100")
		spec.Annotations = annotations
		bundleDir, conf, err := testutil.SetupContainerInRoot(rootDir, spec)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(bundleDir)
		cont, err := container.Create(containerIDs[i], spec, conf, bundleDir, "", "", "")
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

func TestMultiContainerWait(t *testing.T) {
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
	containers := make([]*container.Container, 0, len(containerIDs))
	for i, annotations := range containerAnnotations {
		spec := testutil.NewSpecWithArgs(args[i][0], args[i][1])
		spec.Annotations = annotations
		bundleDir, conf, err := testutil.SetupContainerInRoot(rootDir, spec)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(bundleDir)
		cont, err := container.Create(containerIDs[i], spec, conf, bundleDir, "", "", "")
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
