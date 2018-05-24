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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"context"
	"flag"
	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/control"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/unet"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/cmd"
	"gvisor.googlesource.com/gvisor/runsc/container"
)

func init() {
	log.SetLevel(log.Debug)
}

// writeSpec writes the spec to disk in the given directory.
func writeSpec(dir string, spec *specs.Spec) error {
	b, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(dir, "config.json"), b, 0755)
}

// newSpecWithArgs creates a simple spec with the given args suitable for use
// in tests.
func newSpecWithArgs(args ...string) *specs.Spec {
	spec := &specs.Spec{
		// The host filesystem root is the container root.
		Root: &specs.Root{
			Path:     "/",
			Readonly: true,
		},
		Process: &specs.Process{
			Args: args,
			Env: []string{
				"PATH=" + os.Getenv("PATH"),
			},
		},
	}
	return spec
}

// setupContainer creates a bundle and root dir for the container, generates a
// test config, and writes the spec to config.json in the bundle dir.
func setupContainer(spec *specs.Spec) (rootDir, bundleDir string, conf *boot.Config, err error) {
	rootDir, err = ioutil.TempDir("", "containers")
	if err != nil {
		return "", "", nil, fmt.Errorf("error creating root dir: %v", err)
	}

	bundleDir, err = ioutil.TempDir("", "bundle")
	if err != nil {
		return "", "", nil, fmt.Errorf("error creating bundle dir: %v", err)
	}

	if err = writeSpec(bundleDir, spec); err != nil {
		return "", "", nil, fmt.Errorf("error writing spec: %v", err)
	}

	conf = &boot.Config{
		RootDir: rootDir,
		Network: boot.NetworkNone,
		// Don't add flags when calling subprocesses, since the test
		// runner does not know about all the flags. We control the
		// Config in the subprocess anyways, so it does not matter.
		TestModeNoFlags: true,
	}

	return rootDir, bundleDir, conf, nil
}

// uniqueContainerID generates a unique container id for each test.
//
// The container id is used to create an abstract unix domain socket, which must
// be unique.  While the container forbids creating two containers with the same
// name, sometimes between test runs the socket does not get cleaned up quickly
// enough, causing container creation to fail.
func uniqueContainerID() string {
	return fmt.Sprintf("test-container-%d", time.Now().UnixNano())
}

// waitForProcessList waits for the given process list to show up in the container.
func waitForProcessList(s *container.Container, expected []*control.Process) error {
	var got []*control.Process
	for start := time.Now(); time.Now().Sub(start) < 10*time.Second; {
		var err error
		got, err := s.Processes()
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
		pd1.Time, pd2.Time = "", ""
		pd1.STime, pd2.STime = "", ""
		pd1.C, pd2.C = 0, 0
		if *pd1 != *pd2 {
			return false
		}
	}
	return true
}

func procListToString(pl []*control.Process) string {
	strs := make([]string, 0, len(pl))
	for _, p := range pl {
		strs = append(strs, fmt.Sprintf("%+v", p))
	}
	return fmt.Sprintf("[%s]", strings.Join(strs, ","))
}

// TestLifecycle tests the basic Create/Start/Signal/Destroy container lifecycle.
// It verifies after each step that the container can be loaded from disk, and
// has the correct status.
func TestLifecycle(t *testing.T) {
	// The container will just sleep for a long time.  We will kill it before
	// it finishes sleeping.
	spec := newSpecWithArgs("sleep", "100")

	rootDir, bundleDir, conf, err := setupContainer(spec)
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
	id := uniqueContainerID()
	if _, err := container.Create(id, spec, conf, bundleDir, "", ""); err != nil {
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
	go func() {
		ws, err := s.Wait()
		if err != nil {
			t.Errorf("error waiting on container: %v", err)
		}
		if got, want := ws.Signal(), syscall.SIGTERM; got != want {
			t.Errorf("got signal %v, want %v", got, want)
		}
		wg.Done()
	}()

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
		spec := newSpecWithArgs(test.path)
		rootDir, bundleDir, conf, err := setupContainer(spec)
		if err != nil {
			t.Fatalf("exec: %s, error setting up container: %v", test.path, err)
		}

		ws, err := container.Run(uniqueContainerID(), spec, conf, bundleDir, "", "")

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
	succSpec := newSpecWithArgs("true")

	rootDir, bundleDir, conf, err := setupContainer(succSpec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	ws, err := container.Run(uniqueContainerID(), succSpec, conf, bundleDir, "", "")
	if err != nil {
		t.Fatalf("error running container: %v", err)
	}
	if ws.ExitStatus() != 0 {
		t.Errorf("got exit status %v want %v", ws.ExitStatus(), 0)
	}

	// Second container exits with non-zero status.
	wantStatus := 123
	errSpec := newSpecWithArgs("bash", "-c", fmt.Sprintf("exit %d", wantStatus))

	rootDir2, bundleDir2, conf, err := setupContainer(errSpec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir2)
	defer os.RemoveAll(bundleDir2)

	ws, err = container.Run(uniqueContainerID(), succSpec, conf, bundleDir2, "", "")
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
	spec := newSpecWithArgs("sleep", "100")

	rootDir, bundleDir, conf, err := setupContainer(spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create and start the container.
	s, err := container.Create(uniqueContainerID(), spec, conf, bundleDir, "", "")
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

// TestCapabilities verifies that:
// - Running exec as non-root UID and GID will result in an error (because the
//   executable file can't be read).
// - Running exec as non-root with CAP_DAC_OVERRIDE succeeds because it skips
//   this check.
func TestCapabilities(t *testing.T) {
	const uid = 343
	const gid = 2401
	spec := newSpecWithArgs("sleep", "100")

	// We generate files in the host temporary directory.
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: os.TempDir(),
		Source:      os.TempDir(),
		Type:        "bind",
	})

	rootDir, bundleDir, conf, err := setupContainer(spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create and start the container.
	s, err := container.Create(uniqueContainerID(), spec, conf, bundleDir, "", "")
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
	spec := newSpecWithArgs("true")
	rootDir, bundleDir, conf, err := setupContainer(spec)
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
	id := uniqueContainerID()
	s, err := container.Create(id, spec, conf, bundleDir, socketRelPath, "")
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

func TestSpecUnsupported(t *testing.T) {
	spec := newSpecWithArgs("/bin/true")
	spec.Process.SelinuxLabel = "somelabel"

	// These are normally set by docker and will just cause warnings to be logged.
	spec.Process.ApparmorProfile = "someprofile"
	spec.Linux = &specs.Linux{Seccomp: &specs.LinuxSeccomp{}}

	rootDir, bundleDir, conf, err := setupContainer(spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	id := uniqueContainerID()
	_, err = container.Create(id, spec, conf, bundleDir, "", "")
	if err == nil || !strings.Contains(err.Error(), "is not supported") {
		t.Errorf("container.Create() wrong error, got: %v, want: *is not supported, spec.Process: %+v", err, spec.Process)
	}
}

// TestRunNonRoot checks that sandbox can be configured when running as
// non-priviledged user.
func TestRunNonRoot(t *testing.T) {
	spec := newSpecWithArgs("/bin/true")
	spec.Process.User.UID = 343
	spec.Process.User.GID = 2401

	// User that container runs as can't list '$TMP/blocked' and would fail to
	// mount it.
	dir := path.Join(os.TempDir(), "blocked")
	if err := os.Mkdir(dir, 0700); err != nil {
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

	rootDir, bundleDir, conf, err := setupContainer(spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create, start and wait for the container.
	s, err := container.Create(uniqueContainerID(), spec, conf, bundleDir, "", "")
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer s.Destroy()
	if err := s.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}
	ws, err := s.Wait()
	if err != nil {
		t.Errorf("error waiting on container: %v", err)
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		t.Errorf("container failed, waitStatus: %v", ws)
	}
}

// TestMain acts like runsc if it is called with the "boot" argument, otherwise
// it just runs the tests.  This is required because creating a container will
// call "/proc/self/exe boot".  Normally /proc/self/exe is the runsc binary,
// but for tests we have to fake it.
func TestMain(m *testing.M) {
	// exit writes coverage data before exiting.
	exit := func(status int) {
		os.Exit(status)
	}

	if !flag.Parsed() {
		flag.Parse()
	}

	// If we are passed one of the commands then run it.
	subcommands.Register(new(cmd.Boot), "boot")
	subcommands.Register(new(cmd.Gofer), "gofer")
	switch flag.Arg(0) {
	case "boot", "gofer":
		conf := &boot.Config{
			RootDir: "unused-root-dir",
			Network: boot.NetworkNone,
		}
		var ws syscall.WaitStatus
		subcmdCode := subcommands.Execute(context.Background(), conf, &ws)
		if subcmdCode != subcommands.ExitSuccess {
			panic(fmt.Sprintf("command failed to execute, err: %v", subcmdCode))
		}
		// Container exited. Shut down this process.
		exit(ws.ExitStatus())
	default:
		// Otherwise run the tests.
		exit(m.Run())
	}
}
