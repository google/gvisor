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
	"bytes"
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
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
)

func init() {
	log.SetLevel(log.Debug)
	if err := testutil.ConfigureExePath(); err != nil {
		panic(err.Error())
	}
}

// waitForProcessList waits for the given process list to show up in the container.
func waitForProcessList(cont *Container, expected []*control.Process) error {
	var got []*control.Process
	for start := time.Now(); time.Now().Sub(start) < 10*time.Second; {
		var err error
		got, err = cont.Processes()
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
func getAndCheckProcLists(cont *Container, want []*control.Process) error {
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

// createWriteableOutputFile creates an output file that can be read and
// written to in the sandbox.
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

func waitForFile(f *os.File) error {
	op := func() error {
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		if fi.Size() == 0 {
			return fmt.Errorf("file %q is empty", f.Name())
		}
		return nil
	}

	timeout := 5 * time.Second
	if testutil.RaceEnabled {
		// Race makes slow things even slow, so bump the timeout.
		timeout = 3 * timeout
	}
	return testutil.Poll(op, timeout)
}

// readOutputNum reads a file at given filepath and returns the int at the
// requested position.
func readOutputNum(file string, position int) (int, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, fmt.Errorf("error opening file: %q, %v", file, err)
	}

	// Ensure that there is content in output file.
	if err := waitForFile(f); err != nil {
		return 0, fmt.Errorf("error waiting for output file: %v", err)
	}

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return 0, fmt.Errorf("error reading file: %v", err)
	}
	if len(b) == 0 {
		return 0, fmt.Errorf("error no content was read")
	}

	// Strip leading null bytes caused by file offset not being 0 upon restore.
	b = bytes.Trim(b, "\x00")
	nums := strings.Split(string(b), "\n")

	if position >= len(nums) {
		return 0, fmt.Errorf("position %v is not within the length of content %v", position, nums)
	}
	if position == -1 {
		// Expectation of newline at the end of last position.
		position = len(nums) - 2
	}
	num, err := strconv.Atoi(nums[position])
	if err != nil {
		return 0, fmt.Errorf("error getting number from file: %v", err)
	}
	return num, nil
}

// run starts the sandbox and waits for it to exit, checking that the
// application succeeded.
func run(spec *specs.Spec, conf *boot.Config) error {
	rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		return fmt.Errorf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create, start and wait for the container.
	c, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
	if err != nil {
		return fmt.Errorf("error creating container: %v", err)
	}
	defer c.Destroy()
	if err := c.Start(conf); err != nil {
		return fmt.Errorf("error starting container: %v", err)
	}

	ws, err := c.Wait()
	if err != nil {
		return fmt.Errorf("error waiting on container: %v", err)
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		return fmt.Errorf("container failed, waitStatus: %v", ws)
	}
	return nil
}

type configOption int

const (
	overlay configOption = iota
	kvm
	nonExclusiveFS
)

var noOverlay = []configOption{kvm, nonExclusiveFS}
var all = append(noOverlay, overlay)

// configs generates different configurations to run tests.
func configs(opts ...configOption) []*boot.Config {
	// Always load the default config.
	cs := []*boot.Config{testutil.TestConfig()}

	for _, o := range opts {
		c := testutil.TestConfig()
		switch o {
		case overlay:
			c.Overlay = true
		case kvm:
			// TODO: KVM tests are flaky. Disable until fixed.
			continue

			// TODO: KVM doesn't work with --race.
			if testutil.RaceEnabled {
				continue
			}
			c.Platform = boot.PlatformKVM
		case nonExclusiveFS:
			c.FileAccess = boot.FileAccessShared
		default:
			panic(fmt.Sprintf("unknown config option %v", o))

		}
		cs = append(cs, c)
	}
	return cs
}

// TestLifecycle tests the basic Create/Start/Signal/Destroy container lifecycle.
// It verifies after each step that the container can be loaded from disk, and
// has the correct status.
func TestLifecycle(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)
		// The container will just sleep for a long time.  We will kill it before
		// it finishes sleeping.
		spec := testutil.NewSpecWithArgs("sleep", "100")

		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
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
		c, err := Create(id, spec, conf, bundleDir, "", "")
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer c.Destroy()

		// Load the container from disk and check the status.
		c, err = Load(rootDir, id)
		if err != nil {
			t.Fatalf("error loading container: %v", err)
		}
		if got, want := c.Status, Created; got != want {
			t.Errorf("container status got %v, want %v", got, want)
		}

		// List should return the container id.
		ids, err := List(rootDir)
		if err != nil {
			t.Fatalf("error listing containers: %v", err)
		}
		if got, want := ids, []string{id}; !reflect.DeepEqual(got, want) {
			t.Errorf("container list got %v, want %v", got, want)
		}

		// Start the container.
		if err := c.Start(conf); err != nil {
			t.Fatalf("error starting container: %v", err)
		}

		// Load the container from disk and check the status.
		c, err = Load(rootDir, id)
		if err != nil {
			t.Fatalf("error loading container: %v", err)
		}
		if got, want := c.Status, Running; got != want {
			t.Errorf("container status got %v, want %v", got, want)
		}

		// Verify that "sleep 100" is running.
		if err := waitForProcessList(c, expectedPL); err != nil {
			t.Error(err)
		}

		// Wait on the container.
		var wg sync.WaitGroup
		wg.Add(1)
		ch := make(chan struct{})
		go func() {
			ch <- struct{}{}
			ws, err := c.Wait()
			if err != nil {
				t.Fatalf("error waiting on container: %v", err)
			}
			if got, want := ws.Signal(), syscall.SIGTERM; got != want {
				t.Fatalf("got signal %v, want %v", got, want)
			}
			wg.Done()
		}()

		// Wait a bit to ensure that we've started waiting on the
		// container before we signal.
		<-ch
		time.Sleep(100 * time.Millisecond)
		// Send the container a SIGTERM which will cause it to stop.
		if err := c.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("error sending signal %v to container: %v", syscall.SIGTERM, err)
		}
		// Wait for it to die.
		wg.Wait()

		// Load the container from disk and check the status.
		c, err = Load(rootDir, id)
		if err != nil {
			t.Fatalf("error loading container: %v", err)
		}
		if got, want := c.Status, Stopped; got != want {
			t.Errorf("container status got %v, want %v", got, want)
		}

		// Destroy the container.
		if err := c.Destroy(); err != nil {
			t.Fatalf("error destroying container: %v", err)
		}

		// List should not return the container id.
		ids, err = List(rootDir)
		if err != nil {
			t.Fatalf("error listing containers: %v", err)
		}
		if len(ids) != 0 {
			t.Errorf("expected container list to be empty, but got %v", ids)
		}

		// Loading the container by id should fail.
		if _, err = Load(rootDir, id); err == nil {
			t.Errorf("expected loading destroyed container to fail, but it did not")
		}
	}
}

// Test the we can execute the application with different path formats.
func TestExePath(t *testing.T) {
	for _, conf := range configs(overlay) {
		t.Logf("Running test with conf: %+v", conf)
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
			rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("exec: %s, error setting up container: %v", test.path, err)
			}

			ws, err := Run(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")

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
}

// Test the we can retrieve the application exit status from the container.
func TestAppExitStatus(t *testing.T) {
	// First container will succeed.
	succSpec := testutil.NewSpecWithArgs("true")
	conf := testutil.TestConfig()
	rootDir, bundleDir, err := testutil.SetupContainer(succSpec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	ws, err := Run(testutil.UniqueContainerID(), succSpec, conf, bundleDir, "", "")
	if err != nil {
		t.Fatalf("error running container: %v", err)
	}
	if ws.ExitStatus() != 0 {
		t.Errorf("got exit status %v want %v", ws.ExitStatus(), 0)
	}

	// Second container exits with non-zero status.
	wantStatus := 123
	errSpec := testutil.NewSpecWithArgs("bash", "-c", fmt.Sprintf("exit %d", wantStatus))

	rootDir2, bundleDir2, err := testutil.SetupContainer(errSpec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir2)
	defer os.RemoveAll(bundleDir2)

	ws, err = Run(testutil.UniqueContainerID(), succSpec, conf, bundleDir2, "", "")
	if err != nil {
		t.Fatalf("error running container: %v", err)
	}
	if ws.ExitStatus() != wantStatus {
		t.Errorf("got exit status %v want %v", ws.ExitStatus(), wantStatus)
	}
}

// TestExec verifies that a container can exec a new program.
func TestExec(t *testing.T) {
	for _, conf := range configs(overlay) {
		t.Logf("Running test with conf: %+v", conf)

		const uid = 343
		spec := testutil.NewSpecWithArgs("sleep", "100")

		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		// Create and start the container.
		cont, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
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

		// Verify that "sleep 100" is running.
		if err := waitForProcessList(cont, expectedPL[:1]); err != nil {
			t.Error(err)
		}

		args := &control.ExecArgs{
			Filename:         "/bin/sleep",
			Argv:             []string{"/bin/sleep", "5"},
			WorkingDirectory: "/",
			KUID:             uid,
		}

		// Verify that "sleep 100" and "sleep 5" are running after exec.
		// First, start running exec (whick blocks).
		status := make(chan error, 1)
		go func() {
			exitStatus, err := cont.executeSync(args)
			if err != nil {
				log.Debugf("error executing: %v", err)
				status <- err
			} else if exitStatus != 0 {
				log.Debugf("bad status: %d", exitStatus)
				status <- fmt.Errorf("failed with exit status: %v", exitStatus)
			} else {
				status <- nil
			}
		}()

		if err := waitForProcessList(cont, expectedPL); err != nil {
			t.Fatal(err)
		}

		// Ensure that exec finished without error.
		select {
		case <-time.After(10 * time.Second):
			t.Fatalf("container timed out waiting for exec to finish.")
		case st := <-status:
			if st != nil {
				t.Errorf("container failed to exec %v: %v", args, err)
			}
		}
	}
}

// TestCheckpointRestore creates a container that continuously writes successive integers
// to a file. To test checkpoint and restore functionality, the container is
// checkpointed and the last number printed to the file is recorded. Then, it is restored in two
// new containers and the first number printed from these containers is checked. Both should
// be the next consecutive number after the last number from the checkpointed container.
func TestCheckpointRestore(t *testing.T) {
	// Skip overlay because test requires writing to host file.
	for _, conf := range configs(noOverlay...) {
		t.Logf("Running test with conf: %+v", conf)

		dir, err := ioutil.TempDir(testutil.TmpDir(), "checkpoint-test")
		if err != nil {
			t.Fatalf("ioutil.TempDir failed: %v", err)
		}
		if err := os.Chmod(dir, 0777); err != nil {
			t.Fatalf("error chmoding file: %q, %v", dir, err)
		}

		outputPath := filepath.Join(dir, "output")
		outputFile, err := createWriteableOutputFile(outputPath)
		if err != nil {
			t.Fatalf("error creating output file: %v", err)
		}
		defer outputFile.Close()

		script := fmt.Sprintf("for ((i=0; ;i++)); do echo $i >> %q; sleep 1; done", outputPath)
		spec := testutil.NewSpecWithArgs("bash", "-c", script)
		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		// Create and start the container.
		cont, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer cont.Destroy()
		if err := cont.Start(conf); err != nil {
			t.Fatalf("error starting container: %v", err)
		}

		// Set the image path, which is where the checkpoint image will be saved.
		imagePath := filepath.Join(dir, "test-image-file")

		// Create the image file and open for writing.
		file, err := os.OpenFile(imagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0644)
		if err != nil {
			t.Fatalf("error opening new file at imagePath: %v", err)
		}
		defer file.Close()

		// Wait until application has ran.
		if err := waitForFile(outputFile); err != nil {
			t.Fatalf("Failed to wait for output file: %v", err)
		}

		// Checkpoint running container; save state into new file.
		if err := cont.Checkpoint(file); err != nil {
			t.Fatalf("error checkpointing container to empty file: %v", err)
		}
		defer os.RemoveAll(imagePath)

		lastNum, err := readOutputNum(outputPath, -1)
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
		cont2, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer cont2.Destroy()

		if err := cont2.Restore(spec, conf, imagePath); err != nil {
			t.Fatalf("error restoring container: %v", err)
		}

		// Wait until application has ran.
		if err := waitForFile(outputFile2); err != nil {
			t.Fatalf("Failed to wait for output file: %v", err)
		}

		firstNum, err := readOutputNum(outputPath, 0)
		if err != nil {
			t.Fatalf("error with outputFile: %v", err)
		}

		// Check that lastNum is one less than firstNum and that the container picks
		// up from where it left off.
		if lastNum+1 != firstNum {
			t.Errorf("error numbers not in order, previous: %d, next: %d", lastNum, firstNum)
		}
		cont2.Destroy()

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
		cont3, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer cont3.Destroy()

		if err := cont3.Restore(spec, conf, imagePath); err != nil {
			t.Fatalf("error restoring container: %v", err)
		}

		// Wait until application has ran.
		if err := waitForFile(outputFile3); err != nil {
			t.Fatalf("Failed to wait for output file: %v", err)
		}

		firstNum2, err := readOutputNum(outputPath, 0)
		if err != nil {
			t.Fatalf("error with outputFile: %v", err)
		}

		// Check that lastNum is one less than firstNum and that the container picks
		// up from where it left off.
		if lastNum+1 != firstNum2 {
			t.Errorf("error numbers not in order, previous: %d, next: %d", lastNum, firstNum2)
		}
		cont3.Destroy()
	}
}

// TestUnixDomainSockets checks that Checkpoint/Restore works in cases
// with filesystem Unix Domain Socket use.
func TestUnixDomainSockets(t *testing.T) {
	// Skip overlay because test requires writing to host file.
	for _, conf := range configs(noOverlay...) {
		t.Logf("Running test with conf: %+v", conf)

		// UDS path is limited to 108 chars for compatibility with older systems.
		// Use '/tmp' (instead of testutil.TmpDir) to to ensure the size limit is
		// not exceeded. Assumes '/tmp' exists in the system.
		dir, err := ioutil.TempDir("/tmp", "uds-test")
		if err != nil {
			t.Fatalf("ioutil.TempDir failed: %v", err)
		}
		defer os.RemoveAll(dir)

		outputPath := filepath.Join(dir, "uds_output")
		outputFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0666)
		if err != nil {
			t.Fatalf("error creating output file: %v", err)
		}
		defer outputFile.Close()

		app, err := testutil.FindFile("runsc/container/uds_test_app")
		if err != nil {
			t.Fatal("error finding uds_test_app:", err)
		}

		socketPath := filepath.Join(dir, "uds_socket")
		defer os.Remove(socketPath)

		spec := testutil.NewSpecWithArgs(app, "--file", outputPath, "--socket", socketPath)
		spec.Process.User = specs.User{
			UID: uint32(os.Getuid()),
			GID: uint32(os.Getgid()),
		}
		spec.Mounts = []specs.Mount{{
			Type:        "bind",
			Destination: dir,
			Source:      dir,
		}}

		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		// Create and start the container.
		cont, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer cont.Destroy()
		if err := cont.Start(conf); err != nil {
			t.Fatalf("error starting container: %v", err)
		}

		// Set the image path, the location where the checkpoint image will be saved.
		imagePath := filepath.Join(dir, "test-image-file")

		// Create the image file and open for writing.
		file, err := os.OpenFile(imagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0644)
		if err != nil {
			t.Fatalf("error opening new file at imagePath: %v", err)
		}
		defer file.Close()
		defer os.RemoveAll(imagePath)

		// Wait until application has ran.
		if err := waitForFile(outputFile); err != nil {
			t.Fatalf("Failed to wait for output file: %v", err)
		}

		// Checkpoint running container; save state into new file.
		if err := cont.Checkpoint(file); err != nil {
			t.Fatalf("error checkpointing container to empty file: %v", err)
		}

		// Read last number outputted before checkpoint.
		lastNum, err := readOutputNum(outputPath, -1)
		if err != nil {
			t.Fatalf("error with outputFile: %v", err)
		}

		// Delete and recreate file before restoring.
		if err := os.Remove(outputPath); err != nil {
			t.Fatalf("error removing file")
		}
		outputFile2, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0666)
		if err != nil {
			t.Fatalf("error creating output file: %v", err)
		}
		defer outputFile2.Close()

		// Restore into a new container.
		contRestore, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer contRestore.Destroy()

		if err := contRestore.Restore(spec, conf, imagePath); err != nil {
			t.Fatalf("error restoring container: %v", err)
		}

		// Wait until application has ran.
		if err := waitForFile(outputFile2); err != nil {
			t.Fatalf("Failed to wait for output file: %v", err)
		}

		// Read first number outputted after restore.
		firstNum, err := readOutputNum(outputPath, 0)
		if err != nil {
			t.Fatalf("error with outputFile: %v", err)
		}

		// Check that lastNum is one less than firstNum.
		if lastNum+1 != firstNum {
			t.Errorf("error numbers not consecutive, previous: %d, next: %d", lastNum, firstNum)
		}
		contRestore.Destroy()
	}
}

// TestPauseResume tests that we can successfully pause and resume a container.
// It checks starts running sleep and executes another sleep. It pauses and checks
// that both processes are still running: sleep will be paused and still exist.
// It will then unpause and confirm that both processes are running. Then it will
// wait until one sleep completes and check to make sure the other is running.
func TestPauseResume(t *testing.T) {
	for _, conf := range configs(noOverlay...) {
		t.Logf("Running test with conf: %+v", conf)
		const uid = 343
		spec := testutil.NewSpecWithArgs("sleep", "20")

		lock, err := ioutil.TempFile(testutil.TmpDir(), "lock")
		if err != nil {
			t.Fatalf("error creating output file: %v", err)
		}
		defer lock.Close()

		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		// Create and start the container.
		cont, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
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
				Cmd:  "bash",
			},
		}

		script := fmt.Sprintf("while [[ -f %q ]]; do sleep 0.1; done", lock.Name())
		args := &control.ExecArgs{
			Filename:         "/bin/bash",
			Argv:             []string{"bash", "-c", script},
			WorkingDirectory: "/",
			KUID:             uid,
		}

		// First, start running exec.
		_, err = cont.Execute(args)
		if err != nil {
			t.Fatalf("error executing: %v", err)
		}

		// Verify that "sleep 5" is running.
		if err := waitForProcessList(cont, expectedPL); err != nil {
			t.Fatal(err)
		}

		// Pause the running container.
		if err := cont.Pause(); err != nil {
			t.Errorf("error pausing container: %v", err)
		}
		if got, want := cont.Status, Paused; got != want {
			t.Errorf("container status got %v, want %v", got, want)
		}

		if err := os.Remove(lock.Name()); err != nil {
			t.Fatalf("os.Remove(lock) failed: %v", err)
		}
		// Script loops and sleeps for 100ms. Give a bit a time for it to exit in
		// case pause didn't work.
		time.Sleep(200 * time.Millisecond)

		// Verify that the two processes still exist.
		if err := getAndCheckProcLists(cont, expectedPL); err != nil {
			t.Fatal(err)
		}

		// Resume the running container.
		if err := cont.Resume(); err != nil {
			t.Errorf("error pausing container: %v", err)
		}
		if got, want := cont.Status, Running; got != want {
			t.Errorf("container status got %v, want %v", got, want)
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

		// Verify that deleting the file triggered the process to exit.
		if err := waitForProcessList(cont, expectedPL2); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPauseResumeStatus makes sure that the statuses are set correctly
// with calls to pause and resume and that pausing and resuming only
// occurs given the correct state.
func TestPauseResumeStatus(t *testing.T) {
	spec := testutil.NewSpecWithArgs("sleep", "20")
	conf := testutil.TestConfig()
	rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create and start the container.
	cont, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
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
	if got, want := cont.Status, Paused; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}

	// Try to Pause again. Should cause error.
	if err := cont.Pause(); err == nil {
		t.Errorf("error pausing container that was already paused: %v", err)
	}
	if got, want := cont.Status, Paused; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}

	// Resume the running container.
	if err := cont.Resume(); err != nil {
		t.Errorf("error resuming container: %v", err)
	}
	if got, want := cont.Status, Running; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}

	// Try to resume again. Should cause error.
	if err := cont.Resume(); err == nil {
		t.Errorf("error resuming container already running: %v", err)
	}
	if got, want := cont.Status, Running; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}
}

// TestCapabilities verifies that:
// - Running exec as non-root UID and GID will result in an error (because the
//   executable file can't be read).
// - Running exec as non-root with CAP_DAC_OVERRIDE succeeds because it skips
//   this check.
func TestCapabilities(t *testing.T) {
	// Pick uid/gid different than ours.
	uid := auth.KUID(os.Getuid() + 1)
	gid := auth.KGID(os.Getgid() + 1)

	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		spec := testutil.NewSpecWithArgs("sleep", "100")
		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		// Create and start the container.
		cont, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
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
				Cmd:  "exe",
			},
		}
		if err := waitForProcessList(cont, expectedPL[:1]); err != nil {
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

		args := &control.ExecArgs{
			Filename:         exePath,
			Argv:             []string{exePath},
			WorkingDirectory: "/",
			KUID:             uid,
			KGID:             gid,
			Capabilities:     &auth.TaskCapabilities{},
		}

		// "exe" should fail because we don't have the necessary permissions.
		if _, err := cont.executeSync(args); err == nil {
			t.Fatalf("container executed without error, but an error was expected")
		}

		// Now we run with the capability enabled and should succeed.
		args.Capabilities = &auth.TaskCapabilities{
			EffectiveCaps: auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
		}
		// "exe" should not fail this time.
		if _, err := cont.executeSync(args); err != nil {
			t.Fatalf("container failed to exec %v: %v", args, err)
		}
	}
}

// Test that an tty FD is sent over the console socket if one is provided.
func TestConsoleSocket(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)
		spec := testutil.NewSpecWithArgs("true")
		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
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
		c, err := Create(id, spec, conf, bundleDir, socketRelPath, "")
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		c.Destroy()

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
		if err := c.Destroy(); err != nil {
			t.Fatalf("error destroying container: %v", err)
		}

		// Close socket.
		if err := srv.Close(); err != nil {
			t.Fatalf("error destroying container: %v", err)
		}
	}
}

// TestRunNonRoot checks that sandbox can be configured when running as
// non-privileged user.
func TestRunNonRoot(t *testing.T) {
	for _, conf := range configs(noOverlay...) {
		t.Logf("Running test with conf: %+v", conf)

		spec := testutil.NewSpecWithArgs("/bin/true")
		spec.Process.User.UID = 343
		spec.Process.User.GID = 2401

		// User that container runs as can't list '$TMP/blocked' and would fail to
		// mount it.
		dir, err := ioutil.TempDir(testutil.TmpDir(), "blocked")
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

		if err := run(spec, conf); err != nil {
			t.Fatalf("error running sandbox: %v", err)
		}
	}
}

// TestMountNewDir checks that runsc will create destination directory if it
// doesn't exit.
func TestMountNewDir(t *testing.T) {
	for _, conf := range configs(overlay) {
		t.Logf("Running test with conf: %+v", conf)

		root, err := ioutil.TempDir(testutil.TmpDir(), "root")
		if err != nil {
			t.Fatal("ioutil.TempDir() failed:", err)
		}

		srcDir := path.Join(root, "src", "dir", "anotherdir")
		if err := os.MkdirAll(srcDir, 0755); err != nil {
			t.Fatalf("os.MkDir(%q) failed: %v", srcDir, err)
		}

		mountDir := path.Join(root, "dir", "anotherdir")

		spec := testutil.NewSpecWithArgs("/bin/ls", mountDir)
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: mountDir,
			Source:      srcDir,
			Type:        "bind",
		})

		if err := run(spec, conf); err != nil {
			t.Fatalf("error running sandbox: %v", err)
		}
	}
}

func TestReadonlyRoot(t *testing.T) {
	for _, conf := range configs(overlay) {
		t.Logf("Running test with conf: %+v", conf)

		spec := testutil.NewSpecWithArgs("/bin/touch", "/foo")
		spec.Root.Readonly = true
		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		// Create, start and wait for the container.
		c, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer c.Destroy()
		if err := c.Start(conf); err != nil {
			t.Fatalf("error starting container: %v", err)
		}

		ws, err := c.Wait()
		if err != nil {
			t.Fatalf("error waiting on container: %v", err)
		}
		if !ws.Exited() || syscall.Errno(ws.ExitStatus()) != syscall.EPERM {
			t.Fatalf("container failed, waitStatus: %v", ws)
		}
	}
}

func TestReadonlyMount(t *testing.T) {
	for _, conf := range configs(overlay) {
		t.Logf("Running test with conf: %+v", conf)

		dir, err := ioutil.TempDir(testutil.TmpDir(), "ro-mount")
		spec := testutil.NewSpecWithArgs("/bin/touch", path.Join(dir, "file"))
		if err != nil {
			t.Fatalf("ioutil.TempDir() failed: %v", err)
		}
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: dir,
			Source:      dir,
			Type:        "bind",
			Options:     []string{"ro"},
		})
		spec.Root.Readonly = false

		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		// Create, start and wait for the container.
		c, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer c.Destroy()
		if err := c.Start(conf); err != nil {
			t.Fatalf("error starting container: %v", err)
		}

		ws, err := c.Wait()
		if err != nil {
			t.Fatalf("error waiting on container: %v", err)
		}
		if !ws.Exited() || syscall.Errno(ws.ExitStatus()) != syscall.EPERM {
			t.Fatalf("container failed, waitStatus: %v", ws)
		}
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
		conf := testutil.TestConfig()
		bundleDir, err := testutil.SetupContainerInRoot(rootDir, spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		// Create and start the container.
		cont, err := Create(cid, spec, conf, bundleDir, "", "")
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
		if _, err := Load(rootDir, shortid); err != nil {
			t.Errorf("%q should resolve to %q: %v", shortid, longid, err)
		}
	}

	// These should be ambiguous.
	ambiguous := []string{
		"b",
		"ba",
	}
	for _, shortid := range ambiguous {
		if s, err := Load(rootDir, shortid); err == nil {
			t.Errorf("%q should be ambiguous, but resolved to %q", shortid, s.ID)
		}
	}
}

// Check that modifications to a volume mount are propigated into and out of
// the sandbox.
func TestContainerVolumeContentsShared(t *testing.T) {
	// Only run this test with shared file access, since that is the only
	// behavior it is testing.
	conf := testutil.TestConfig()
	conf.FileAccess = boot.FileAccessShared
	t.Logf("Running test with conf: %+v", conf)

	// Main process just sleeps. We will use "exec" to probe the state of
	// the filesystem.
	spec := testutil.NewSpecWithArgs("sleep", "1000")

	dir, err := ioutil.TempDir(testutil.TmpDir(), "root-fs-test")
	if err != nil {
		t.Fatalf("TempDir failed: %v", err)
	}

	rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create and start the container.
	c, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer c.Destroy()
	if err := c.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// File that will be used to check consistency inside/outside sandbox.
	filename := filepath.Join(dir, "file")

	// File does not exist yet. Reading from the sandbox should fail.
	argsTestFile := &control.ExecArgs{
		Filename: "/usr/bin/test",
		Argv:     []string{"test", "-f", filename},
	}
	if ws, err := c.executeSync(argsTestFile); err != nil {
		t.Fatalf("unexpected error testing file %q: %v", filename, err)
	} else if ws.ExitStatus() == 0 {
		t.Errorf("test %q exited with code %v, wanted not zero", ws.ExitStatus(), err)
	}

	// Create the file from outside of the sandbox.
	if err := ioutil.WriteFile(filename, []byte("foobar"), 0777); err != nil {
		t.Fatalf("error writing to file %q: %v", filename, err)
	}

	// Now we should be able to test the file from within the sandbox.
	if ws, err := c.executeSync(argsTestFile); err != nil {
		t.Fatalf("unexpected error testing file %q: %v", filename, err)
	} else if ws.ExitStatus() != 0 {
		t.Errorf("test %q exited with code %v, wanted zero", filename, ws.ExitStatus())
	}

	// Rename the file from outside of the sandbox.
	newFilename := filepath.Join(dir, "newfile")
	if err := os.Rename(filename, newFilename); err != nil {
		t.Fatalf("os.Rename(%q, %q) failed: %v", filename, newFilename, err)
	}

	// File should no longer exist at the old path within the sandbox.
	if ws, err := c.executeSync(argsTestFile); err != nil {
		t.Fatalf("unexpected error testing file %q: %v", filename, err)
	} else if ws.ExitStatus() == 0 {
		t.Errorf("test %q exited with code %v, wanted not zero", filename, ws.ExitStatus())
	}

	// We should be able to test the new filename from within the sandbox.
	argsTestNewFile := &control.ExecArgs{
		Filename: "/usr/bin/test",
		Argv:     []string{"test", "-f", newFilename},
	}
	if ws, err := c.executeSync(argsTestNewFile); err != nil {
		t.Fatalf("unexpected error testing file %q: %v", newFilename, err)
	} else if ws.ExitStatus() != 0 {
		t.Errorf("test %q exited with code %v, wanted zero", newFilename, ws.ExitStatus())
	}

	// Delete the renamed file from outside of the sandbox.
	if err := os.Remove(newFilename); err != nil {
		t.Fatalf("error removing file %q: %v", filename, err)
	}

	// Renamed file should no longer exist at the old path within the sandbox.
	if ws, err := c.executeSync(argsTestNewFile); err != nil {
		t.Fatalf("unexpected error testing file %q: %v", newFilename, err)
	} else if ws.ExitStatus() == 0 {
		t.Errorf("test %q exited with code %v, wanted not zero", newFilename, ws.ExitStatus())
	}

	// Now create the file from WITHIN the sandbox.
	argsTouch := &control.ExecArgs{
		Filename: "/usr/bin/touch",
		Argv:     []string{"touch", filename},
		KUID:     auth.KUID(os.Getuid()),
		KGID:     auth.KGID(os.Getgid()),
	}
	if ws, err := c.executeSync(argsTouch); err != nil {
		t.Fatalf("unexpected error touching file %q: %v", filename, err)
	} else if ws.ExitStatus() != 0 {
		t.Errorf("touch %q exited with code %v, wanted zero", filename, ws.ExitStatus())
	}

	// File should exist outside the sandbox.
	if _, err := os.Stat(filename); err != nil {
		t.Errorf("stat %q got error %v, wanted nil", filename, err)
	}

	// File should exist outside the sandbox.
	if _, err := os.Stat(filename); err != nil {
		t.Errorf("stat %q got error %v, wanted nil", filename, err)
	}

	// Delete the file from within the sandbox.
	argsRemove := &control.ExecArgs{
		Filename: "/bin/rm",
		Argv:     []string{"rm", filename},
	}
	if ws, err := c.executeSync(argsRemove); err != nil {
		t.Fatalf("unexpected error removing file %q: %v", filename, err)
	} else if ws.ExitStatus() != 0 {
		t.Errorf("remove %q exited with code %v, wanted zero", filename, ws.ExitStatus())
	}

	// File should not exist outside the sandbox.
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		t.Errorf("stat %q got error %v, wanted ErrNotExist", filename, err)
	}
}

func TestGoferExits(t *testing.T) {
	spec := testutil.NewSpecWithArgs("/bin/sleep", "10000")
	conf := testutil.TestConfig()
	rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create and start the container.
	c, err := Create(testutil.UniqueContainerID(), spec, conf, bundleDir, "", "")
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer c.Destroy()
	if err := c.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// Kill sandbox and expect gofer to exit on its own.
	sandboxProc, err := os.FindProcess(c.Sandbox.Pid)
	if err != nil {
		t.Fatalf("error finding sandbox process: %v", err)
	}
	if err := sandboxProc.Kill(); err != nil {
		t.Fatalf("error killing sandbox process: %v", err)
	}

	_, _, err = testutil.RetryEintr(func() (uintptr, uintptr, error) {
		cpid, err := syscall.Wait4(c.GoferPid, nil, 0, nil)
		return uintptr(cpid), 0, err
	})
	if err != nil && err != syscall.ECHILD {
		t.Errorf("error waiting for gofer to exit: %v", err)
	}
}

// executeSync synchronously executes a new process.
func (cont *Container) executeSync(args *control.ExecArgs) (syscall.WaitStatus, error) {
	pid, err := cont.Execute(args)
	if err != nil {
		return 0, fmt.Errorf("error executing: %v", err)
	}
	ws, err := cont.WaitPID(pid, true /* clearStatus */)
	if err != nil {
		return 0, fmt.Errorf("error waiting: %v", err)
	}
	return ws, nil
}

func TestMain(m *testing.M) {
	testutil.RunAsRoot()
	stop := testutil.StartReaper()
	defer stop()
	os.Exit(m.Run())
}
