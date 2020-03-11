// Copyright 2018 The gVisor Authors.
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
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/boot/platforms"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/testutil"
)

// waitForProcessList waits for the given process list to show up in the container.
func waitForProcessList(cont *Container, want []*control.Process) error {
	cb := func() error {
		got, err := cont.Processes()
		if err != nil {
			err = fmt.Errorf("error getting process data from container: %v", err)
			return &backoff.PermanentError{Err: err}
		}
		if r, err := procListsEqual(got, want); !r {
			return fmt.Errorf("container got process list: %s, want: %s: error: %v",
				procListToString(got), procListToString(want), err)
		}
		return nil
	}
	// Gives plenty of time as tests can run slow under --race.
	return testutil.Poll(cb, 30*time.Second)
}

func waitForProcessCount(cont *Container, want int) error {
	cb := func() error {
		pss, err := cont.Processes()
		if err != nil {
			err = fmt.Errorf("error getting process data from container: %v", err)
			return &backoff.PermanentError{Err: err}
		}
		if got := len(pss); got != want {
			log.Infof("Waiting for process count to reach %d. Current: %d", want, got)
			return fmt.Errorf("wrong process count, got: %d, want: %d", got, want)
		}
		return nil
	}
	// Gives plenty of time as tests can run slow under --race.
	return testutil.Poll(cb, 30*time.Second)
}

func blockUntilWaitable(pid int) error {
	_, _, err := specutils.RetryEintr(func() (uintptr, uintptr, error) {
		var err error
		_, _, err1 := syscall.Syscall6(syscall.SYS_WAITID, 1, uintptr(pid), 0, syscall.WEXITED|syscall.WNOWAIT, 0, 0)
		if err1 != 0 {
			err = err1
		}
		return 0, 0, err
	})
	return err
}

// procListsEqual is used to check whether 2 Process lists are equal for all
// implemented fields.
func procListsEqual(got, want []*control.Process) (bool, error) {
	if len(got) != len(want) {
		return false, nil
	}
	for i := range got {
		pd1 := got[i]
		pd2 := want[i]
		// Zero out timing dependant fields.
		pd1.Time = ""
		pd1.STime = ""
		pd1.C = 0
		// Ignore TTY field too, since it's not relevant in the cases
		// where we use this method. Tests that care about the TTY
		// field should check for it themselves.
		pd1.TTY = ""
		pd1Json, err := control.ProcessListToJSON([]*control.Process{pd1})
		if err != nil {
			return false, err
		}
		pd2Json, err := control.ProcessListToJSON([]*control.Process{pd2})
		if err != nil {
			return false, err
		}
		if pd1Json != pd2Json {
			return false, nil
		}
	}
	return true, nil
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

func waitForFileNotEmpty(f *os.File) error {
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

	return testutil.Poll(op, 30*time.Second)
}

func waitForFileExist(path string) error {
	op := func() error {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return err
		}
		return nil
	}

	return testutil.Poll(op, 30*time.Second)
}

// readOutputNum reads a file at given filepath and returns the int at the
// requested position.
func readOutputNum(file string, position int) (int, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, fmt.Errorf("error opening file: %q, %v", file, err)
	}

	// Ensure that there is content in output file.
	if err := waitForFileNotEmpty(f); err != nil {
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
	args := Args{
		ID:        testutil.UniqueContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
		Attached:  true,
	}
	ws, err := Run(conf, args)
	if err != nil {
		return fmt.Errorf("running container: %v", err)
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
			// TODO(b/112165693): KVM tests are flaky. Disable until fixed.
			continue

			c.Platform = platforms.KVM
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
	// Start the child reaper.
	childReaper := &testutil.Reaper{}
	childReaper.Start()
	defer childReaper.Stop()

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
				UID:     0,
				PID:     1,
				PPID:    0,
				C:       0,
				Cmd:     "sleep",
				Threads: []kernel.ThreadID{1},
			},
		}
		// Create the container.
		args := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		c, err := New(conf, args)
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer c.Destroy()

		// Load the container from disk and check the status.
		c, err = Load(rootDir, args.ID)
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
		if got, want := ids, []string{args.ID}; !reflect.DeepEqual(got, want) {
			t.Errorf("container list got %v, want %v", got, want)
		}

		// Start the container.
		if err := c.Start(conf); err != nil {
			t.Fatalf("error starting container: %v", err)
		}

		// Load the container from disk and check the status.
		c, err = Load(rootDir, args.ID)
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
		if err := c.SignalContainer(syscall.SIGTERM, false); err != nil {
			t.Fatalf("error sending signal %v to container: %v", syscall.SIGTERM, err)
		}
		// Wait for it to die.
		wg.Wait()

		// Load the container from disk and check the status.
		c, err = Load(rootDir, args.ID)
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
		if _, err = Load(rootDir, args.ID); err == nil {
			t.Errorf("expected loading destroyed container to fail, but it did not")
		}
	}
}

// Test the we can execute the application with different path formats.
func TestExePath(t *testing.T) {
	// Create two directories that will be prepended to PATH.
	firstPath, err := ioutil.TempDir(testutil.TmpDir(), "first")
	if err != nil {
		t.Fatal(err)
	}
	secondPath, err := ioutil.TempDir(testutil.TmpDir(), "second")
	if err != nil {
		t.Fatal(err)
	}

	// Create two minimal executables in the second path, two of which
	// will be masked by files in first path.
	for _, p := range []string{"unmasked", "masked1", "masked2"} {
		path := filepath.Join(secondPath, p)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0777)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := io.WriteString(f, "#!/bin/true\n"); err != nil {
			t.Fatal(err)
		}
	}

	// Create a non-executable file in the first path which masks a healthy
	// executable in the second.
	nonExecutable := filepath.Join(firstPath, "masked1")
	f2, err := os.OpenFile(nonExecutable, os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		t.Fatal(err)
	}
	f2.Close()

	// Create a non-regular file in the first path which masks a healthy
	// executable in the second.
	nonRegular := filepath.Join(firstPath, "masked2")
	if err := os.Mkdir(nonRegular, 0777); err != nil {
		t.Fatal(err)
	}

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

			{path: "unmasked", success: true},
			{path: filepath.Join(firstPath, "unmasked"), success: false},
			{path: filepath.Join(secondPath, "unmasked"), success: true},

			{path: "masked1", success: true},
			{path: filepath.Join(firstPath, "masked1"), success: false},
			{path: filepath.Join(secondPath, "masked1"), success: true},

			{path: "masked2", success: true},
			{path: filepath.Join(firstPath, "masked2"), success: false},
			{path: filepath.Join(secondPath, "masked2"), success: true},
		} {
			spec := testutil.NewSpecWithArgs(test.path)
			spec.Process.Env = []string{
				fmt.Sprintf("PATH=%s:%s:%s", firstPath, secondPath, os.Getenv("PATH")),
			}

			rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("exec: %s, error setting up container: %v", test.path, err)
			}

			args := Args{
				ID:        testutil.UniqueContainerID(),
				Spec:      spec,
				BundleDir: bundleDir,
				Attached:  true,
			}
			ws, err := Run(conf, args)

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

	args := Args{
		ID:        testutil.UniqueContainerID(),
		Spec:      succSpec,
		BundleDir: bundleDir,
		Attached:  true,
	}
	ws, err := Run(conf, args)
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

	args2 := Args{
		ID:        testutil.UniqueContainerID(),
		Spec:      errSpec,
		BundleDir: bundleDir2,
		Attached:  true,
	}
	ws, err = Run(conf, args2)
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
		args := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		cont, err := New(conf, args)
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
				UID:     0,
				PID:     1,
				PPID:    0,
				C:       0,
				Cmd:     "sleep",
				Threads: []kernel.ThreadID{1},
			},
			{
				UID:     uid,
				PID:     2,
				PPID:    0,
				C:       0,
				Cmd:     "sleep",
				Threads: []kernel.ThreadID{2},
			},
		}

		// Verify that "sleep 100" is running.
		if err := waitForProcessList(cont, expectedPL[:1]); err != nil {
			t.Error(err)
		}

		execArgs := &control.ExecArgs{
			Filename:         "/bin/sleep",
			Argv:             []string{"/bin/sleep", "5"},
			WorkingDirectory: "/",
			KUID:             uid,
		}

		// Verify that "sleep 100" and "sleep 5" are running after exec.
		// First, start running exec (whick blocks).
		status := make(chan error, 1)
		go func() {
			exitStatus, err := cont.executeSync(execArgs)
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

// TestKillPid verifies that we can signal individual exec'd processes.
func TestKillPid(t *testing.T) {
	for _, conf := range configs(overlay) {
		t.Logf("Running test with conf: %+v", conf)

		app, err := testutil.FindFile("runsc/container/test_app/test_app")
		if err != nil {
			t.Fatal("error finding test_app:", err)
		}

		const nProcs = 4
		spec := testutil.NewSpecWithArgs(app, "task-tree", "--depth", strconv.Itoa(nProcs-1), "--width=1", "--pause=true")
		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		// Create and start the container.
		args := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		cont, err := New(conf, args)
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer cont.Destroy()
		if err := cont.Start(conf); err != nil {
			t.Fatalf("error starting container: %v", err)
		}

		// Verify that all processes are running.
		if err := waitForProcessCount(cont, nProcs); err != nil {
			t.Fatalf("timed out waiting for processes to start: %v", err)
		}

		// Kill the child process with the largest PID.
		procs, err := cont.Processes()
		if err != nil {
			t.Fatalf("failed to get process list: %v", err)
		}
		var pid int32
		for _, p := range procs {
			if pid < int32(p.PID) {
				pid = int32(p.PID)
			}
		}
		if err := cont.SignalProcess(syscall.SIGKILL, pid); err != nil {
			t.Fatalf("failed to signal process %d: %v", pid, err)
		}

		// Verify that one process is gone.
		if err := waitForProcessCount(cont, nProcs-1); err != nil {
			t.Fatal(err)
		}

		procs, err = cont.Processes()
		if err != nil {
			t.Fatalf("failed to get process list: %v", err)
		}
		for _, p := range procs {
			if pid == int32(p.PID) {
				t.Fatalf("pid %d is still alive, which should be killed", pid)
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
		args := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		cont, err := New(conf, args)
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
		if err := waitForFileNotEmpty(outputFile); err != nil {
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
		args2 := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		cont2, err := New(conf, args2)
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer cont2.Destroy()

		if err := cont2.Restore(spec, conf, imagePath); err != nil {
			t.Fatalf("error restoring container: %v", err)
		}

		// Wait until application has ran.
		if err := waitForFileNotEmpty(outputFile2); err != nil {
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
		args3 := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		cont3, err := New(conf, args3)
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer cont3.Destroy()

		if err := cont3.Restore(spec, conf, imagePath); err != nil {
			t.Fatalf("error restoring container: %v", err)
		}

		// Wait until application has ran.
		if err := waitForFileNotEmpty(outputFile3); err != nil {
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
		// Use '/tmp' (instead of testutil.TmpDir) to ensure the size limit is
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

		app, err := testutil.FindFile("runsc/container/test_app/test_app")
		if err != nil {
			t.Fatal("error finding test_app:", err)
		}

		socketPath := filepath.Join(dir, "uds_socket")
		defer os.Remove(socketPath)

		spec := testutil.NewSpecWithArgs(app, "uds", "--file", outputPath, "--socket", socketPath)
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
		args := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		cont, err := New(conf, args)
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
		if err := waitForFileNotEmpty(outputFile); err != nil {
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
		argsRestore := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		contRestore, err := New(conf, argsRestore)
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer contRestore.Destroy()

		if err := contRestore.Restore(spec, conf, imagePath); err != nil {
			t.Fatalf("error restoring container: %v", err)
		}

		// Wait until application has ran.
		if err := waitForFileNotEmpty(outputFile2); err != nil {
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
// The container will keep touching a file to indicate it's running. The test
// pauses the container, removes the file, and checks that it doesn't get
// recreated. Then it resumes the container, verify that the file gets created
// again.
func TestPauseResume(t *testing.T) {
	for _, conf := range configs(noOverlay...) {
		t.Run(fmt.Sprintf("conf: %+v", conf), func(t *testing.T) {
			t.Logf("Running test with conf: %+v", conf)

			tmpDir, err := ioutil.TempDir(testutil.TmpDir(), "lock")
			if err != nil {
				t.Fatalf("error creating temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			running := path.Join(tmpDir, "running")
			script := fmt.Sprintf("while [[ true ]]; do touch %q; sleep 0.1; done", running)
			spec := testutil.NewSpecWithArgs("/bin/bash", "-c", script)

			rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer os.RemoveAll(rootDir)
			defer os.RemoveAll(bundleDir)

			// Create and start the container.
			args := Args{
				ID:        testutil.UniqueContainerID(),
				Spec:      spec,
				BundleDir: bundleDir,
			}
			cont, err := New(conf, args)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer cont.Destroy()
			if err := cont.Start(conf); err != nil {
				t.Fatalf("error starting container: %v", err)
			}

			// Wait until container starts running, observed by the existence of running
			// file.
			if err := waitForFileExist(running); err != nil {
				t.Errorf("error waiting for container to start: %v", err)
			}

			// Pause the running container.
			if err := cont.Pause(); err != nil {
				t.Errorf("error pausing container: %v", err)
			}
			if got, want := cont.Status, Paused; got != want {
				t.Errorf("container status got %v, want %v", got, want)
			}

			if err := os.Remove(running); err != nil {
				t.Fatalf("os.Remove(%q) failed: %v", running, err)
			}
			// Script touches the file every 100ms. Give a bit a time for it to run to
			// catch the case that pause didn't work.
			time.Sleep(200 * time.Millisecond)
			if _, err := os.Stat(running); !os.IsNotExist(err) {
				t.Fatalf("container did not pause: file exist check: %v", err)
			}

			// Resume the running container.
			if err := cont.Resume(); err != nil {
				t.Errorf("error pausing container: %v", err)
			}
			if got, want := cont.Status, Running; got != want {
				t.Errorf("container status got %v, want %v", got, want)
			}

			// Verify that the file is once again created by container.
			if err := waitForFileExist(running); err != nil {
				t.Fatalf("error resuming container: file exist check: %v", err)
			}
		})
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
	args := Args{
		ID:        testutil.UniqueContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont, err := New(conf, args)
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
		args := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		cont, err := New(conf, args)
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
				UID:     0,
				PID:     1,
				PPID:    0,
				C:       0,
				Cmd:     "sleep",
				Threads: []kernel.ThreadID{1},
			},
			{
				UID:     uid,
				PID:     2,
				PPID:    0,
				C:       0,
				Cmd:     "exe",
				Threads: []kernel.ThreadID{2},
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

		execArgs := &control.ExecArgs{
			Filename:         exePath,
			Argv:             []string{exePath},
			WorkingDirectory: "/",
			KUID:             uid,
			KGID:             gid,
			Capabilities:     &auth.TaskCapabilities{},
		}

		// "exe" should fail because we don't have the necessary permissions.
		if _, err := cont.executeSync(execArgs); err == nil {
			t.Fatalf("container executed without error, but an error was expected")
		}

		// Now we run with the capability enabled and should succeed.
		execArgs.Capabilities = &auth.TaskCapabilities{
			EffectiveCaps: auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
		}
		// "exe" should not fail this time.
		if _, err := cont.executeSync(execArgs); err != nil {
			t.Fatalf("container failed to exec %v: %v", args, err)
		}
	}
}

// TestRunNonRoot checks that sandbox can be configured when running as
// non-privileged user.
func TestRunNonRoot(t *testing.T) {
	for _, conf := range configs(noOverlay...) {
		t.Logf("Running test with conf: %+v", conf)

		spec := testutil.NewSpecWithArgs("/bin/true")

		// Set a random user/group with no access to "blocked" dir.
		spec.Process.User.UID = 343
		spec.Process.User.GID = 2401
		spec.Process.Capabilities = nil

		// User running inside container can't list '$TMP/blocked' and would fail to
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

		src, err := ioutil.TempDir(testutil.TmpDir(), "src")
		if err != nil {
			t.Fatalf("ioutil.TempDir() failed: %v", err)
		}

		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: dir,
			Source:      src,
			Type:        "bind",
		})

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
		args := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		c, err := New(conf, args)
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

func TestUIDMap(t *testing.T) {
	for _, conf := range configs(noOverlay...) {
		t.Logf("Running test with conf: %+v", conf)
		testDir, err := ioutil.TempDir(testutil.TmpDir(), "test-mount")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(testDir)
		testFile := path.Join(testDir, "testfile")

		spec := testutil.NewSpecWithArgs("touch", "/tmp/testfile")
		uid := os.Getuid()
		gid := os.Getgid()
		spec.Linux = &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.UserNamespace},
				{Type: specs.PIDNamespace},
				{Type: specs.MountNamespace},
			},
			UIDMappings: []specs.LinuxIDMapping{
				{
					ContainerID: 0,
					HostID:      uint32(uid),
					Size:        1,
				},
			},
			GIDMappings: []specs.LinuxIDMapping{
				{
					ContainerID: 0,
					HostID:      uint32(gid),
					Size:        1,
				},
			},
		}

		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: "/tmp",
			Source:      testDir,
			Type:        "bind",
		})

		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		// Create, start and wait for the container.
		args := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		c, err := New(conf, args)
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
		if !ws.Exited() || ws.ExitStatus() != 0 {
			t.Fatalf("container failed, waitStatus: %v", ws)
		}
		st := syscall.Stat_t{}
		if err := syscall.Stat(testFile, &st); err != nil {
			t.Fatalf("error stat /testfile: %v", err)
		}

		if st.Uid != uint32(uid) || st.Gid != uint32(gid) {
			t.Fatalf("UID: %d (%d) GID: %d (%d)", st.Uid, uid, st.Gid, gid)
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
		args := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		c, err := New(conf, args)
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
	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer os.RemoveAll(rootDir)

	conf := testutil.TestConfig()
	conf.RootDir = rootDir

	cids := []string{
		"foo-" + testutil.UniqueContainerID(),
		"bar-" + testutil.UniqueContainerID(),
		"baz-" + testutil.UniqueContainerID(),
	}
	for _, cid := range cids {
		spec := testutil.NewSpecWithArgs("sleep", "100")
		bundleDir, err := testutil.SetupBundleDir(spec)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(bundleDir)

		// Create and start the container.
		args := Args{
			ID:        cid,
			Spec:      spec,
			BundleDir: bundleDir,
		}
		cont, err := New(conf, args)
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
	args := Args{
		ID:        testutil.UniqueContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	c, err := New(conf, args)
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

	err = blockUntilWaitable(c.GoferPid)
	if err != nil && err != syscall.ECHILD {
		t.Errorf("error waiting for gofer to exit: %v", err)
	}
}

func TestRootNotMount(t *testing.T) {
	appSym, err := testutil.FindFile("runsc/container/test_app/test_app")
	if err != nil {
		t.Fatal("error finding test_app:", err)
	}

	app, err := filepath.EvalSymlinks(appSym)
	if err != nil {
		t.Fatalf("error resolving %q symlink: %v", appSym, err)
	}
	log.Infof("App path %q is a symlink to %q", appSym, app)

	static, err := testutil.IsStatic(app)
	if err != nil {
		t.Fatalf("error reading application binary: %v", err)
	}
	if !static {
		// This happens during race builds; we cannot map in shared
		// libraries also, so we need to skip the test.
		t.Skip()
	}

	root := filepath.Dir(app)
	exe := "/" + filepath.Base(app)
	log.Infof("Executing %q in %q", exe, root)

	spec := testutil.NewSpecWithArgs(exe, "help")
	spec.Root.Path = root
	spec.Root.Readonly = true
	spec.Mounts = nil

	conf := testutil.TestConfig()
	if err := run(spec, conf); err != nil {
		t.Fatalf("error running sandbox: %v", err)
	}
}

func TestUserLog(t *testing.T) {
	app, err := testutil.FindFile("runsc/container/test_app/test_app")
	if err != nil {
		t.Fatal("error finding test_app:", err)
	}

	// sched_rr_get_interval = 148 - not implemented in gvisor.
	spec := testutil.NewSpecWithArgs(app, "syscall", "--syscall=148")
	conf := testutil.TestConfig()
	rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	dir, err := ioutil.TempDir(testutil.TmpDir(), "user_log_test")
	if err != nil {
		t.Fatalf("error creating tmp dir: %v", err)
	}
	userLog := filepath.Join(dir, "user.log")

	// Create, start and wait for the container.
	args := Args{
		ID:        testutil.UniqueContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
		UserLog:   userLog,
		Attached:  true,
	}
	ws, err := Run(conf, args)
	if err != nil {
		t.Fatalf("error running container: %v", err)
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		t.Fatalf("container failed, waitStatus: %v", ws)
	}

	out, err := ioutil.ReadFile(userLog)
	if err != nil {
		t.Fatalf("error opening user log file %q: %v", userLog, err)
	}
	if want := "Unsupported syscall: sched_rr_get_interval"; !strings.Contains(string(out), want) {
		t.Errorf("user log file doesn't contain %q, out: %s", want, string(out))
	}
}

func TestWaitOnExitedSandbox(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		// Run a shell that sleeps for 1 second and then exits with a
		// non-zero code.
		const wantExit = 17
		cmd := fmt.Sprintf("sleep 1; exit %d", wantExit)
		spec := testutil.NewSpecWithArgs("/bin/sh", "-c", cmd)
		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		// Create and Start the container.
		args := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		c, err := New(conf, args)
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		defer c.Destroy()
		if err := c.Start(conf); err != nil {
			t.Fatalf("error starting container: %v", err)
		}

		// Wait on the sandbox. This will make an RPC to the sandbox
		// and get the actual exit status of the application.
		ws, err := c.Wait()
		if err != nil {
			t.Fatalf("error waiting on container: %v", err)
		}
		if got := ws.ExitStatus(); got != wantExit {
			t.Errorf("got exit status %d, want %d", got, wantExit)
		}

		// Now the sandbox has exited, but the zombie sandbox process
		// still exists. Calling Wait() now will return the sandbox
		// exit status.
		ws, err = c.Wait()
		if err != nil {
			t.Fatalf("error waiting on container: %v", err)
		}
		if got := ws.ExitStatus(); got != wantExit {
			t.Errorf("got exit status %d, want %d", got, wantExit)
		}
	}
}

func TestDestroyNotStarted(t *testing.T) {
	spec := testutil.NewSpecWithArgs("/bin/sleep", "100")
	conf := testutil.TestConfig()
	rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create the container and check that it can be destroyed.
	args := Args{
		ID:        testutil.UniqueContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	c, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	if err := c.Destroy(); err != nil {
		t.Fatalf("deleting non-started container failed: %v", err)
	}
}

// TestDestroyStarting attempts to force a race between start and destroy.
func TestDestroyStarting(t *testing.T) {
	for i := 0; i < 10; i++ {
		spec := testutil.NewSpecWithArgs("/bin/sleep", "100")
		conf := testutil.TestConfig()
		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		// Create the container and check that it can be destroyed.
		args := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		c, err := New(conf, args)
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}

		// Container is not thread safe, so load another instance to run in
		// concurrently.
		startCont, err := Load(rootDir, args.ID)
		if err != nil {
			t.Fatalf("error loading container: %v", err)
		}
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Ignore failures, start can fail if destroy runs first.
			startCont.Start(conf)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Destroy(); err != nil {
				t.Errorf("deleting non-started container failed: %v", err)
			}
		}()
		wg.Wait()
	}
}

func TestCreateWorkingDir(t *testing.T) {
	for _, conf := range configs(overlay) {
		t.Logf("Running test with conf: %+v", conf)

		tmpDir, err := ioutil.TempDir(testutil.TmpDir(), "cwd-create")
		if err != nil {
			t.Fatalf("ioutil.TempDir() failed: %v", err)
		}
		dir := path.Join(tmpDir, "new/working/dir")

		// touch will fail if the directory doesn't exist.
		spec := testutil.NewSpecWithArgs("/bin/touch", path.Join(dir, "file"))
		spec.Process.Cwd = dir
		spec.Root.Readonly = true

		if err := run(spec, conf); err != nil {
			t.Fatalf("Error running container: %v", err)
		}
	}
}

// TestMountPropagation verifies that mount propagates to slave but not to
// private mounts.
func TestMountPropagation(t *testing.T) {
	// Setup dir structure:
	//   - src: is mounted as shared and is used as source for both private and
	//     slave mounts
	//   - dir: will be bind mounted inside src and should propagate to slave
	tmpDir, err := ioutil.TempDir(testutil.TmpDir(), "mount")
	if err != nil {
		t.Fatalf("ioutil.TempDir() failed: %v", err)
	}
	src := filepath.Join(tmpDir, "src")
	srcMnt := filepath.Join(src, "mnt")
	dir := filepath.Join(tmpDir, "dir")
	for _, path := range []string{src, srcMnt, dir} {
		if err := os.MkdirAll(path, 0777); err != nil {
			t.Fatalf("MkdirAll(%q): %v", path, err)
		}
	}
	dirFile := filepath.Join(dir, "file")
	f, err := os.Create(dirFile)
	if err != nil {
		t.Fatalf("os.Create(%q): %v", dirFile, err)
	}
	f.Close()

	// Setup src as a shared mount.
	if err := syscall.Mount(src, src, "bind", syscall.MS_BIND, ""); err != nil {
		t.Fatalf("mount(%q, %q, MS_BIND): %v", dir, srcMnt, err)
	}
	if err := syscall.Mount("", src, "", syscall.MS_SHARED, ""); err != nil {
		t.Fatalf("mount(%q, MS_SHARED): %v", srcMnt, err)
	}

	spec := testutil.NewSpecWithArgs("sleep", "1000")

	priv := filepath.Join(tmpDir, "priv")
	slave := filepath.Join(tmpDir, "slave")
	spec.Mounts = []specs.Mount{
		{
			Source:      src,
			Destination: priv,
			Type:        "bind",
			Options:     []string{"private"},
		},
		{
			Source:      src,
			Destination: slave,
			Type:        "bind",
			Options:     []string{"slave"},
		},
	}

	conf := testutil.TestConfig()
	rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	args := Args{
		ID:        testutil.UniqueContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("creating container: %v", err)
	}
	defer cont.Destroy()

	if err := cont.Start(conf); err != nil {
		t.Fatalf("starting container: %v", err)
	}

	// After the container is started, mount dir inside source and check what
	// happens to both destinations.
	if err := syscall.Mount(dir, srcMnt, "bind", syscall.MS_BIND, ""); err != nil {
		t.Fatalf("mount(%q, %q, MS_BIND): %v", dir, srcMnt, err)
	}

	// Check that mount didn't propagate to private mount.
	privFile := filepath.Join(priv, "mnt", "file")
	execArgs := &control.ExecArgs{
		Filename: "/usr/bin/test",
		Argv:     []string{"test", "!", "-f", privFile},
	}
	if ws, err := cont.executeSync(execArgs); err != nil || ws != 0 {
		t.Fatalf("exec: test ! -f %q, ws: %v, err: %v", privFile, ws, err)
	}

	// Check that mount propagated to slave mount.
	slaveFile := filepath.Join(slave, "mnt", "file")
	execArgs = &control.ExecArgs{
		Filename: "/usr/bin/test",
		Argv:     []string{"test", "-f", slaveFile},
	}
	if ws, err := cont.executeSync(execArgs); err != nil || ws != 0 {
		t.Fatalf("exec: test -f %q, ws: %v, err: %v", privFile, ws, err)
	}
}

func TestMountSymlink(t *testing.T) {
	for _, conf := range configs(overlay) {
		t.Logf("Running test with conf: %+v", conf)

		dir, err := ioutil.TempDir(testutil.TmpDir(), "mount-symlink")
		if err != nil {
			t.Fatalf("ioutil.TempDir() failed: %v", err)
		}

		source := path.Join(dir, "source")
		target := path.Join(dir, "target")
		for _, path := range []string{source, target} {
			if err := os.MkdirAll(path, 0777); err != nil {
				t.Fatalf("os.MkdirAll(): %v", err)
			}
		}
		f, err := os.Create(path.Join(source, "file"))
		if err != nil {
			t.Fatalf("os.Create(): %v", err)
		}
		f.Close()

		link := path.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("os.Symlink(%q, %q): %v", target, link, err)
		}

		spec := testutil.NewSpecWithArgs("/bin/sleep", "1000")

		// Mount to a symlink to ensure the mount code will follow it and mount
		// at the symlink target.
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Type:        "bind",
			Destination: link,
			Source:      source,
		})

		rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(rootDir)
		defer os.RemoveAll(bundleDir)

		args := Args{
			ID:        testutil.UniqueContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		cont, err := New(conf, args)
		if err != nil {
			t.Fatalf("creating container: %v", err)
		}
		defer cont.Destroy()

		if err := cont.Start(conf); err != nil {
			t.Fatalf("starting container: %v", err)
		}

		// Check that symlink was resolved and mount was created where the symlink
		// is pointing to.
		file := path.Join(target, "file")
		execArgs := &control.ExecArgs{
			Filename: "/usr/bin/test",
			Argv:     []string{"test", "-f", file},
		}
		if ws, err := cont.executeSync(execArgs); err != nil || ws != 0 {
			t.Fatalf("exec: test -f %q, ws: %v, err: %v", file, ws, err)
		}
	}
}

// Check that --net-raw disables the CAP_NET_RAW capability.
func TestNetRaw(t *testing.T) {
	capNetRaw := strconv.FormatUint(bits.MaskOf64(int(linux.CAP_NET_RAW)), 10)
	app, err := testutil.FindFile("runsc/container/test_app/test_app")
	if err != nil {
		t.Fatal("error finding test_app:", err)
	}

	for _, enableRaw := range []bool{true, false} {
		conf := testutil.TestConfig()
		conf.EnableRaw = enableRaw

		test := "--enabled"
		if !enableRaw {
			test = "--disabled"
		}

		spec := testutil.NewSpecWithArgs(app, "capability", test, capNetRaw)
		if err := run(spec, conf); err != nil {
			t.Fatalf("Error running container: %v", err)
		}
	}
}

// TestOverlayfsStaleRead most basic test that '--overlayfs-stale-read' works.
func TestOverlayfsStaleRead(t *testing.T) {
	conf := testutil.TestConfig()
	conf.OverlayfsStaleRead = true

	in, err := ioutil.TempFile(testutil.TmpDir(), "stale-read.in")
	if err != nil {
		t.Fatalf("ioutil.TempFile() failed: %v", err)
	}
	defer in.Close()
	if _, err := in.WriteString("stale data"); err != nil {
		t.Fatalf("in.Write() failed: %v", err)
	}

	out, err := ioutil.TempFile(testutil.TmpDir(), "stale-read.out")
	if err != nil {
		t.Fatalf("ioutil.TempFile() failed: %v", err)
	}
	defer out.Close()

	const want = "foobar"
	cmd := fmt.Sprintf("cat %q >&2 && echo %q> %q && cp %q %q", in.Name(), want, in.Name(), in.Name(), out.Name())
	spec := testutil.NewSpecWithArgs("/bin/bash", "-c", cmd)
	if err := run(spec, conf); err != nil {
		t.Fatalf("Error running container: %v", err)
	}

	gotBytes, err := ioutil.ReadAll(out)
	if err != nil {
		t.Fatalf("out.Read() failed: %v", err)
	}
	got := strings.TrimSpace(string(gotBytes))
	if want != got {
		t.Errorf("Wrong content in out file, got: %q. want: %q", got, want)
	}
}

// TestTTYField checks TTY field returned by container.Processes().
func TestTTYField(t *testing.T) {
	stop := testutil.StartReaper()
	defer stop()

	testApp, err := testutil.FindFile("runsc/container/test_app/test_app")
	if err != nil {
		t.Fatal("error finding test_app:", err)
	}

	testCases := []struct {
		name         string
		useTTY       bool
		wantTTYField string
	}{
		{
			name:         "no tty",
			useTTY:       false,
			wantTTYField: "?",
		},
		{
			name:         "tty used",
			useTTY:       true,
			wantTTYField: "pts/0",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			conf := testutil.TestConfig()

			// We will run /bin/sleep, possibly with an open TTY.
			cmd := []string{"/bin/sleep", "10000"}
			if test.useTTY {
				// Run inside the "pty-runner".
				cmd = append([]string{testApp, "pty-runner"}, cmd...)
			}

			spec := testutil.NewSpecWithArgs(cmd...)
			rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer os.RemoveAll(rootDir)
			defer os.RemoveAll(bundleDir)

			// Create and start the container.
			args := Args{
				ID:        testutil.UniqueContainerID(),
				Spec:      spec,
				BundleDir: bundleDir,
			}
			c, err := New(conf, args)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer c.Destroy()
			if err := c.Start(conf); err != nil {
				t.Fatalf("error starting container: %v", err)
			}

			// Wait for sleep to be running, and check the TTY
			// field.
			var gotTTYField string
			cb := func() error {
				ps, err := c.Processes()
				if err != nil {
					err = fmt.Errorf("error getting process data from container: %v", err)
					return &backoff.PermanentError{Err: err}
				}
				for _, p := range ps {
					if strings.Contains(p.Cmd, "sleep") {
						gotTTYField = p.TTY
						return nil
					}
				}
				return fmt.Errorf("sleep not running")
			}
			if err := testutil.Poll(cb, 30*time.Second); err != nil {
				t.Fatalf("error waiting for sleep process: %v", err)
			}

			if gotTTYField != test.wantTTYField {
				t.Errorf("tty field got %q, want %q", gotTTYField, test.wantTTYField)
			}
		})
	}
}

// executeSync synchronously executes a new process.
func (cont *Container) executeSync(args *control.ExecArgs) (syscall.WaitStatus, error) {
	pid, err := cont.Execute(args)
	if err != nil {
		return 0, fmt.Errorf("error executing: %v", err)
	}
	ws, err := cont.WaitPID(pid)
	if err != nil {
		return 0, fmt.Errorf("error waiting: %v", err)
	}
	return ws, nil
}

func TestMain(m *testing.M) {
	log.SetLevel(log.Debug)
	flag.Parse()
	if err := testutil.ConfigureExePath(); err != nil {
		panic(err.Error())
	}
	specutils.MaybeRunAsRoot()
	os.Exit(m.Run())
}
