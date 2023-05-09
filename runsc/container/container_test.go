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
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestMain(m *testing.M) {
	config.RegisterFlags(flag.CommandLine)
	log.SetLevel(log.Debug)
	if err := testutil.ConfigureExePath(); err != nil {
		panic(err.Error())
	}
	if err := specutils.MaybeRunAsRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running as root: %v", err)
		os.Exit(123)
	}
	os.Exit(m.Run())
}

func execute(conf *config.Config, cont *Container, name string, arg ...string) (unix.WaitStatus, error) {
	args := &control.ExecArgs{
		Filename: name,
		Argv:     append([]string{name}, arg...),
	}
	return cont.executeSync(conf, args)
}

// executeCombinedOutput executes a process in the container and captures
// stdout and stderr. If execFile is supplied, a host file will be executed.
// Otherwise, the name argument is used to resolve the executable in the guest.
func executeCombinedOutput(conf *config.Config, cont *Container, execFile *os.File, name string, arg ...string) ([]byte, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer r.Close()

	// Unset the filename when we execute via FD.
	if execFile != nil {
		name = ""
	}
	args := &control.ExecArgs{
		Filename: name,
		Argv:     append([]string{name}, arg...),
		FilePayload: control.NewFilePayload(map[int]*os.File{
			0: os.Stdin, 1: w, 2: w,
		}, execFile),
	}
	ws, err := cont.executeSync(conf, args)
	w.Close()
	if err != nil {
		return nil, err
	}
	if ws != 0 {
		return nil, fmt.Errorf("exec failed, status: %v", ws)
	}

	out, err := ioutil.ReadAll(r)
	return out, err
}

// executeSync synchronously executes a new process.
func (c *Container) executeSync(conf *config.Config, args *control.ExecArgs) (unix.WaitStatus, error) {
	pid, err := c.Execute(conf, args)
	if err != nil {
		return 0, fmt.Errorf("error executing: %v", err)
	}
	ws, err := c.WaitPID(pid)
	if err != nil {
		return 0, fmt.Errorf("error waiting: %v", err)
	}
	return ws, nil
}

// waitForProcessList waits for the given process list to show up in the container.
func waitForProcessList(cont *Container, want []*control.Process) error {
	cb := func() error {
		got, err := cont.Processes()
		if err != nil {
			err = fmt.Errorf("error getting process data from container: %w", err)
			return &backoff.PermanentError{Err: err}
		}
		if !procListsEqual(got, want) {
			return fmt.Errorf("container got process list: %s, want: %s", procListToString(got), procListToString(want))
		}
		return nil
	}
	// Gives plenty of time as tests can run slow under --race.
	return testutil.Poll(cb, 30*time.Second)
}

// waitForProcess waits for the given process to show up in the container.
func waitForProcess(cont *Container, want *control.Process) error {
	cb := func() error {
		gots, err := cont.Processes()
		if err != nil {
			err = fmt.Errorf("error getting process data from container: %w", err)
			return &backoff.PermanentError{Err: err}
		}
		for _, got := range gots {
			if procEqual(got, want) {
				return nil
			}
		}
		return fmt.Errorf("container got process list: %s, want: %+v", procListToString(gots), want)
	}
	// Gives plenty of time as tests can run slow under --race.
	return testutil.Poll(cb, 30*time.Second)
}

func waitForProcessCount(cont *Container, want int) error {
	cb := func() error {
		pss, err := cont.Processes()
		if err != nil {
			err = fmt.Errorf("error getting process data from container: %w", err)
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
		_, _, err1 := unix.Syscall6(unix.SYS_WAITID, 1, uintptr(pid), 0, unix.WEXITED|unix.WNOWAIT, 0, 0)
		if err1 != 0 {
			err = err1
		}
		return 0, 0, err
	})
	return err
}

// execPS executes `ps` inside the container and return the processes.
func execPS(conf *config.Config, c *Container) ([]*control.Process, error) {
	out, err := executeCombinedOutput(conf, c, nil, "/bin/ps", "-e")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("missing header: %q", lines)
	}
	procs := make([]*control.Process, 0, len(lines)-1)
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			return nil, fmt.Errorf("malformed line: %s", line)
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, err
		}
		cmd := fields[3]
		// Fill only the fields we need thus far.
		procs = append(procs, &control.Process{
			PID: kernel.ThreadID(pid),
			Cmd: cmd,
		})
	}
	return procs, nil
}

// procListsEqual is used to check whether 2 Process lists are equal. Fields
// set to -1 in wants are ignored. Timestamp and threads fields are always
// ignored.
func procListsEqual(gots, wants []*control.Process) bool {
	if len(gots) != len(wants) {
		return false
	}
	for i := range gots {
		if !procEqual(gots[i], wants[i]) {
			return false
		}
	}
	return true
}

func procEqual(got, want *control.Process) bool {
	if want.UID != math.MaxUint32 && want.UID != got.UID {
		return false
	}
	if want.PID != -1 && want.PID != got.PID {
		return false
	}
	if want.PPID != -1 && want.PPID != got.PPID {
		return false
	}
	if len(want.TTY) != 0 && want.TTY != got.TTY {
		return false
	}
	if len(want.Cmd) != 0 && want.Cmd != got.Cmd {
		return false
	}
	return true
}

type processBuilder struct {
	process control.Process
}

func newProcessBuilder() *processBuilder {
	return &processBuilder{
		process: control.Process{
			UID:  math.MaxUint32,
			PID:  -1,
			PPID: -1,
		},
	}
}

func (p *processBuilder) Cmd(cmd string) *processBuilder {
	p.process.Cmd = cmd
	return p
}

func (p *processBuilder) PID(pid kernel.ThreadID) *processBuilder {
	p.process.PID = pid
	return p
}

func (p *processBuilder) PPID(ppid kernel.ThreadID) *processBuilder {
	p.process.PPID = ppid
	return p
}

func (p *processBuilder) UID(uid auth.KUID) *processBuilder {
	p.process.UID = uid
	return p
}

func (p *processBuilder) Process() *control.Process {
	return &p.process
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
func run(spec *specs.Spec, conf *config.Config) error {
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		return fmt.Errorf("error setting up container: %v", err)
	}
	defer cleanup()

	// Create, start and wait for the container.
	args := Args{
		ID:        testutil.RandomContainerID(),
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

// platforms must be provided by the BUILD rule, or all platforms are included.
var platforms = flag.String("test_platforms", os.Getenv("TEST_PLATFORMS"), "Platforms to test with.")

// configs generates different configurations to run tests.
func configs(t *testing.T, noOverlay bool) map[string]*config.Config {
	var ps []string
	if *platforms == "" {
		ps = platform.List()
	} else {
		ps = strings.Split(*platforms, ",")
	}

	// Non-overlay versions.
	cs := make(map[string]*config.Config)
	for _, p := range ps {
		c := testutil.TestConfig(t)
		c.Overlay2 = config.Overlay2{RootMount: false, SubMounts: false, Medium: ""}
		c.Platform = p
		cs[p] = c
	}

	// Overlay versions.
	if !noOverlay {
		for _, p := range ps {
			c := testutil.TestConfig(t)
			c.Platform = p
			c.Overlay2 = config.Overlay2{RootMount: true, SubMounts: true, Medium: "memory"}
			cs[p+"-overlay"] = c
		}
	}

	return cs
}

// sleepSpec generates a spec with sleep 1000 and a conf.
func sleepSpecConf(t *testing.T) (*specs.Spec, *config.Config) {
	return testutil.NewSpecWithArgs("sleep", "1000"), testutil.TestConfig(t)
}

// TestLifecycle tests the basic Create/Start/Signal/Destroy container lifecycle.
// It verifies after each step that the container can be loaded from disk, and
// has the correct status.
func TestLifecycle(t *testing.T) {
	// Start the child reaper.
	childReaper := &testutil.Reaper{}
	childReaper.Start()
	defer childReaper.Stop()

	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			// The container will just sleep for a long time.  We will kill it before
			// it finishes sleeping.
			spec, _ := sleepSpecConf(t)

			rootDir, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			// expectedPL lists the expected process state of the container.
			expectedPL := []*control.Process{
				newProcessBuilder().Cmd("sleep").Process(),
			}
			// Create the container.
			args := Args{
				ID:        testutil.RandomContainerID(),
				Spec:      spec,
				BundleDir: bundleDir,
			}
			c, err := New(conf, args)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer c.Destroy()

			// Load the container from disk and check the status.
			c, err = Load(rootDir, FullID{ContainerID: args.ID}, LoadOpts{})
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
			fullID := FullID{
				SandboxID:   args.ID,
				ContainerID: args.ID,
			}
			if got, want := ids, []FullID{fullID}; !reflect.DeepEqual(got, want) {
				t.Errorf("container list got %v, want %v", got, want)
			}

			// Start the container.
			if err := c.Start(conf); err != nil {
				t.Fatalf("error starting container: %v", err)
			}

			// Load the container from disk and check the status.
			c, err = Load(rootDir, fullID, LoadOpts{Exact: true})
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
			ch := make(chan error)
			go func() {
				ws, err := c.Wait()
				if err != nil {
					ch <- err
					return
				}
				if got, want := ws.Signal(), unix.SIGTERM; got != want {
					ch <- fmt.Errorf("got signal %v, want %v", got, want)
					return
				}
				ch <- nil
			}()

			// Wait a bit to ensure that we've started waiting on
			// the container before we signal.
			time.Sleep(time.Second)

			// Send the container a SIGTERM which will cause it to stop.
			if err := c.SignalContainer(unix.SIGTERM, false); err != nil {
				t.Fatalf("error sending signal %v to container: %v", unix.SIGTERM, err)
			}

			// Wait for it to die.
			if err := <-ch; err != nil {
				t.Fatalf("error waiting for container: %v", err)
			}

			// Load the container from disk and check the status.
			c, err = Load(rootDir, fullID, LoadOpts{Exact: true})
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
			if _, err = Load(rootDir, fullID, LoadOpts{Exact: true}); err == nil {
				t.Errorf("expected loading destroyed container to fail, but it did not")
			}
		})
	}
}

// Test the we can execute the application with different path formats.
func TestExePath(t *testing.T) {
	// Create two directories that will be prepended to PATH.
	firstPath, err := ioutil.TempDir(testutil.TmpDir(), "first")
	if err != nil {
		t.Fatalf("error creating temporary directory: %v", err)
	}
	defer os.RemoveAll(firstPath)
	secondPath, err := ioutil.TempDir(testutil.TmpDir(), "second")
	if err != nil {
		t.Fatalf("error creating temporary directory: %v", err)
	}
	defer os.RemoveAll(secondPath)

	// Create two minimal executables in the second path, two of which
	// will be masked by files in first path.
	for _, p := range []string{"unmasked", "masked1", "masked2"} {
		path := filepath.Join(secondPath, p)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0777)
		if err != nil {
			t.Fatalf("error opening path: %v", err)
		}
		defer f.Close()
		if _, err := io.WriteString(f, "#!/bin/true\n"); err != nil {
			t.Fatalf("error writing contents: %v", err)
		}
	}

	// Create a non-executable file in the first path which masks a healthy
	// executable in the second.
	nonExecutable := filepath.Join(firstPath, "masked1")
	f2, err := os.OpenFile(nonExecutable, os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		t.Fatalf("error opening file: %v", err)
	}
	f2.Close()

	// Create a non-regular file in the first path which masks a healthy
	// executable in the second.
	nonRegular := filepath.Join(firstPath, "masked2")
	if err := os.Mkdir(nonRegular, 0777); err != nil {
		t.Fatalf("error making directory: %v", err)
	}

	configs := map[string]*config.Config{
		"default": testutil.TestConfig(t),
		"overlay": testutil.TestConfig(t),
	}
	configs["default"].Overlay2 = config.Overlay2{RootMount: false, SubMounts: false, Medium: ""}
	configs["overlay"].Overlay2 = config.Overlay2{RootMount: true, SubMounts: true, Medium: "memory"}

	for name, conf := range configs {
		t.Run(name, func(t *testing.T) {
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
				name := fmt.Sprintf("path=%s,success=%t", test.path, test.success)
				t.Run(name, func(t *testing.T) {
					spec := testutil.NewSpecWithArgs(test.path)
					spec.Process.Env = []string{
						fmt.Sprintf("PATH=%s:%s:%s", firstPath, secondPath, os.Getenv("PATH")),
					}

					err := run(spec, conf)
					if test.success {
						if err != nil {
							t.Errorf("exec: error running container: %v", err)
						}
					} else if err == nil {
						t.Errorf("exec: got: no error, want: error")
					}
				})
			}
		})
	}
}

// Test the we can retrieve the application exit status from the container.
func TestAppExitStatus(t *testing.T) {
	// First container will succeed.
	succSpec := testutil.NewSpecWithArgs("true")
	conf := testutil.TestConfig(t)
	_, bundleDir, cleanup, err := testutil.SetupContainer(succSpec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
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

	_, bundleDir2, cleanup2, err := testutil.SetupContainer(errSpec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup2()

	args2 := Args{
		ID:        testutil.RandomContainerID(),
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
	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			dir, err := ioutil.TempDir(testutil.TmpDir(), "exec-test")
			if err != nil {
				t.Fatalf("error creating temporary directory: %v", err)
			}
			// Note that some shells may exec the final command in a sequence as
			// an optimization. We avoid this here by adding the exit 0.
			cmd := fmt.Sprintf("ln -s /bin/true %q/symlink && sleep 100 && exit 0", dir)
			spec := testutil.NewSpecWithArgs("sh", "-c", cmd)

			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			// Create and start the container.
			args := Args{
				ID:        testutil.RandomContainerID(),
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

			// Wait until sleep is running to ensure the symlink was created.
			expectedPL := []*control.Process{
				newProcessBuilder().Cmd("sh").Process(),
				newProcessBuilder().Cmd("sleep").Process(),
			}
			if err := waitForProcessList(cont, expectedPL); err != nil {
				t.Fatalf("waitForProcessList: %v", err)
			}

			for _, tc := range []struct {
				name string
				args control.ExecArgs
			}{
				{
					name: "complete",
					args: control.ExecArgs{
						Filename: "/bin/true",
						Argv:     []string{"/bin/true"},
					},
				},
				{
					name: "filename",
					args: control.ExecArgs{
						Filename: "/bin/true",
					},
				},
				{
					name: "argv",
					args: control.ExecArgs{
						Argv: []string{"/bin/true"},
					},
				},
				{
					name: "filename resolution",
					args: control.ExecArgs{
						Filename: "true",
						Envv:     []string{"PATH=/bin"},
					},
				},
				{
					name: "argv resolution",
					args: control.ExecArgs{
						Argv: []string{"true"},
						Envv: []string{"PATH=/bin"},
					},
				},
				{
					name: "argv symlink",
					args: control.ExecArgs{
						Argv: []string{filepath.Join(dir, "symlink")},
					},
				},
				{
					name: "working dir",
					args: control.ExecArgs{
						Argv:             []string{"/bin/sh", "-c", `if [[ "${PWD}" != "/tmp" ]]; then exit 1; fi`},
						WorkingDirectory: "/tmp",
					},
				},
				{
					name: "user",
					args: control.ExecArgs{
						Argv: []string{"/bin/sh", "-c", `if [[ "$(id -u)" != "343" ]]; then exit 1; fi`},
						KUID: 343,
					},
				},
				{
					name: "group",
					args: control.ExecArgs{
						Argv: []string{"/bin/sh", "-c", `if [[ "$(id -g)" != "343" ]]; then exit 1; fi`},
						KGID: 343,
					},
				},
				{
					name: "env",
					args: control.ExecArgs{
						Argv: []string{"/bin/sh", "-c", `if [[ "${FOO}" != "123" ]]; then exit 1; fi`},
						Envv: []string{"FOO=123"},
					},
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					// t.Parallel()
					if ws, err := cont.executeSync(conf, &tc.args); err != nil {
						t.Fatalf("executeAsync(%+v): %v", tc.args, err)
					} else if ws != 0 {
						t.Fatalf("executeAsync(%+v) failed with exit: %v", tc.args, ws)
					}
				})
			}

			// Test for exec failure with an non-existent file.
			t.Run("nonexist", func(t *testing.T) {
				// b/179114837 found by Syzkaller that causes nil pointer panic when
				// trying to dec-ref an unix socket FD.
				fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fds[0])

				_, err = cont.executeSync(conf, &control.ExecArgs{
					Argv: []string{"/nonexist"},
					FilePayload: control.NewFilePayload(map[int]*os.File{
						0: os.NewFile(uintptr(fds[1]), "sock"),
					}, nil),
				})
				want := "failed to load /nonexist"
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("executeSync: want err containing %q; got err = %q", want, err)
				}
			})
		})
	}
}

// TestExecProcList verifies that a container can exec a new program and it
// shows correcly in the process list.
func TestExecProcList(t *testing.T) {
	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			const uid = 343
			spec, _ := sleepSpecConf(t)

			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			// Create and start the container.
			args := Args{
				ID:        testutil.RandomContainerID(),
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

			execArgs := &control.ExecArgs{
				Filename:         "/bin/sleep",
				Argv:             []string{"/bin/sleep", "5"},
				WorkingDirectory: "/",
				KUID:             uid,
			}

			// Verify that "sleep 100" and "sleep 5" are running after exec. First,
			// start running exec (which blocks).
			ch := make(chan error)
			go func() {
				exitStatus, err := cont.executeSync(conf, execArgs)
				if err != nil {
					ch <- err
				} else if exitStatus != 0 {
					ch <- fmt.Errorf("failed with exit status: %v", exitStatus)
				} else {
					ch <- nil
				}
			}()

			// expectedPL lists the expected process state of the container.
			expectedPL := []*control.Process{
				newProcessBuilder().PID(1).PPID(0).Cmd("sleep").UID(0).Process(),
				newProcessBuilder().PID(2).PPID(0).Cmd("sleep").UID(uid).Process(),
			}
			if err := waitForProcessList(cont, expectedPL); err != nil {
				t.Fatalf("error waiting for processes: %v", err)
			}
		})
	}
}

// TestKillPid verifies that we can signal individual exec'd processes.
func TestKillPid(t *testing.T) {
	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			app, err := testutil.FindFile("test/cmd/test_app/test_app")
			if err != nil {
				t.Fatal("error finding test_app:", err)
			}

			const nProcs = 4
			spec := testutil.NewSpecWithArgs(app, "task-tree", "--depth", strconv.Itoa(nProcs-1), "--width=1", "--pause=true")
			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			// Create and start the container.
			args := Args{
				ID:        testutil.RandomContainerID(),
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
			t.Logf("current process list: %v", procs)
			var pid int32
			for _, p := range procs {
				if pid < int32(p.PID) {
					pid = int32(p.PID)
				}
			}
			if err := cont.SignalProcess(unix.SIGKILL, pid); err != nil {
				t.Fatalf("failed to signal process %d: %v", pid, err)
			}

			// Verify that one process is gone.
			if err := waitForProcessCount(cont, nProcs-1); err != nil {
				procs, procsErr := cont.Processes()
				t.Fatalf("error waiting for processes: %v; current processes: %v / %v", err, procs, procsErr)
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
		})
	}
}

// TestCheckpointRestore creates a container that continuously writes successive
// integers to a file. To test checkpoint and restore functionality, the
// container is checkpointed and the last number printed to the file is
// recorded. Then, it is restored in two new containers and the first number
// printed from these containers is checked. Both should be the next consecutive
// number after the last number from the checkpointed container.
func TestCheckpointRestore(t *testing.T) {
	// Skip overlay because test requires writing to host file.
	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			dir, err := ioutil.TempDir(testutil.TmpDir(), "checkpoint-test")
			if err != nil {
				t.Fatalf("ioutil.TempDir failed: %v", err)
			}
			defer os.RemoveAll(dir)
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
			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			// Create and start the container.
			args := Args{
				ID:        testutil.RandomContainerID(),
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
				ID:        testutil.RandomContainerID(),
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
				ID:        testutil.RandomContainerID(),
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
		})
	}
}

// TestUnixDomainSockets checks that Checkpoint/Restore works in cases
// with filesystem Unix Domain Socket use.
func TestUnixDomainSockets(t *testing.T) {
	// Skip overlay because test requires writing to host file.
	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
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

			app, err := testutil.FindFile("test/cmd/test_app/test_app")
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

			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			// Create and start the container.
			args := Args{
				ID:        testutil.RandomContainerID(),
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
				ID:        testutil.RandomContainerID(),
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
		})
	}
}

// TestPauseResume tests that we can successfully pause and resume a container.
// The container will keep touching a file to indicate it's running. The test
// pauses the container, removes the file, and checks that it doesn't get
// recreated. Then it resumes the container, verify that the file gets created
// again.
func TestPauseResume(t *testing.T) {
	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			tmpDir, err := ioutil.TempDir(testutil.TmpDir(), "lock")
			if err != nil {
				t.Fatalf("error creating temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			running := path.Join(tmpDir, "running")
			script := fmt.Sprintf("while [[ true ]]; do touch %q; sleep 0.1; done", running)
			spec := testutil.NewSpecWithArgs("/bin/bash", "-c", script)

			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			// Create and start the container.
			args := Args{
				ID:        testutil.RandomContainerID(),
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
	spec, conf := sleepSpecConf(t)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	// Create and start the container.
	args := Args{
		ID:        testutil.RandomContainerID(),
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
//   - Running exec as non-root UID and GID will result in an error (because the
//     executable file can't be read).
//   - Running exec as non-root with CAP_DAC_OVERRIDE succeeds because it skips
//     this check.
func TestCapabilities(t *testing.T) {
	// Pick uid/gid different than ours.
	uid := auth.KUID(os.Getuid() + 1)
	gid := auth.KGID(os.Getgid() + 1)

	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			spec, _ := sleepSpecConf(t)
			rootDir, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			// Create and start the container.
			args := Args{
				ID:        testutil.RandomContainerID(),
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
				newProcessBuilder().Cmd("sleep").Process(),
			}
			if err := waitForProcessList(cont, expectedPL); err != nil {
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
			if err := os.Chmod(rootDir, 0755); err != nil {
				t.Fatal(err)
			}

			execArgs := &control.ExecArgs{
				Filename:         exePath,
				Argv:             []string{exePath},
				WorkingDirectory: "/",
				KUID:             uid,
				KGID:             gid,
				Capabilities:     &auth.TaskCapabilities{},
			}

			// "exe" should fail because we don't have the necessary permissions.
			if _, err := cont.executeSync(conf, execArgs); err == nil {
				t.Fatalf("container executed without error, but an error was expected")
			}

			// Now we run with the capability enabled and should succeed.
			execArgs.Capabilities = &auth.TaskCapabilities{
				EffectiveCaps: auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
			}
			// "exe" should not fail this time.
			if _, err := cont.executeSync(conf, execArgs); err != nil {
				t.Fatalf("container failed to exec %v: %v", args, err)
			}
		})
	}
}

// TestRunNonRoot checks that sandbox can be configured when running as
// non-privileged user.
func TestRunNonRoot(t *testing.T) {
	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
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
		})
	}
}

// TestMountNewDir checks that runsc will create destination directory if it
// doesn't exit.
func TestMountNewDir(t *testing.T) {
	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
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
			// Extra points for creating the mount with a readonly root.
			spec.Root.Readonly = true

			if err := run(spec, conf); err != nil {
				t.Fatalf("error running sandbox: %v", err)
			}
		})
	}
}

func TestReadonlyRoot(t *testing.T) {
	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			spec, _ := sleepSpecConf(t)
			spec.Root.Readonly = true

			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			args := Args{
				ID:        testutil.RandomContainerID(),
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

			// Read mounts to check that root is readonly.
			out, err := executeCombinedOutput(conf, c, nil, "/bin/sh", "-c", "mount | grep ' / ' | grep -o -e '(.*)'")
			if err != nil {
				t.Fatalf("exec failed: %v", err)
			}
			t.Logf("root mount options: %q", out)
			if !strings.Contains(string(out), "ro") {
				t.Errorf("root not mounted readonly: %q", out)
			}

			// Check that file cannot be created.
			ws, err := execute(conf, c, "/bin/touch", "/foo")
			if err != nil {
				t.Fatalf("touch file in ro mount: %v", err)
			}
			if !ws.Exited() || unix.Errno(ws.ExitStatus()) != unix.EPERM {
				t.Fatalf("wrong waitStatus: %v", ws)
			}
		})
	}
}

func TestReadonlyMount(t *testing.T) {
	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			dir, err := ioutil.TempDir(testutil.TmpDir(), "ro-mount")
			if err != nil {
				t.Fatalf("ioutil.TempDir() failed: %v", err)
			}
			spec, _ := sleepSpecConf(t)
			spec.Mounts = append(spec.Mounts, specs.Mount{
				Destination: dir,
				Source:      dir,
				Type:        "bind",
				Options:     []string{"ro"},
			})
			spec.Root.Readonly = false

			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			args := Args{
				ID:        testutil.RandomContainerID(),
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

			// Read mounts to check that volume is readonly.
			cmd := fmt.Sprintf("mount | grep ' %s ' | grep -o -e '(.*)'", dir)
			out, err := executeCombinedOutput(conf, c, nil, "/bin/sh", "-c", cmd)
			if err != nil {
				t.Fatalf("exec failed, err: %v", err)
			}
			t.Logf("mount options: %q", out)
			if !strings.Contains(string(out), "ro") {
				t.Errorf("volume not mounted readonly: %q", out)
			}

			// Check that file cannot be created.
			ws, err := execute(conf, c, "/bin/touch", path.Join(dir, "file"))
			if err != nil {
				t.Fatalf("touch file in ro mount: %v", err)
			}
			if !ws.Exited() || unix.Errno(ws.ExitStatus()) != unix.EPERM {
				t.Fatalf("wrong WaitStatus: %v", ws)
			}
		})
	}
}

func TestUIDMap(t *testing.T) {
	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			testDir, err := ioutil.TempDir(testutil.TmpDir(), "test-mount")
			if err != nil {
				t.Fatalf("ioutil.TempDir() failed: %v", err)
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

			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			// Create, start and wait for the container.
			args := Args{
				ID:        testutil.RandomContainerID(),
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
			st := unix.Stat_t{}
			if err := unix.Stat(testFile, &st); err != nil {
				t.Fatalf("error stat /testfile: %v", err)
			}

			if st.Uid != uint32(uid) || st.Gid != uint32(gid) {
				t.Fatalf("UID: %d (%d) GID: %d (%d)", st.Uid, uid, st.Gid, gid)
			}
		})
	}
}

// TestAbbreviatedIDs checks that runsc supports using abbreviated container
// IDs in place of full IDs.
func TestAbbreviatedIDs(t *testing.T) {
	rootDir, cleanup, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer cleanup()

	conf := testutil.TestConfig(t)
	conf.RootDir = rootDir

	cids := []string{
		"foo-" + testutil.RandomContainerID(),
		"bar-" + testutil.RandomContainerID(),
		"baz-" + testutil.RandomContainerID(),
	}
	for _, cid := range cids {
		spec, _ := sleepSpecConf(t)
		bundleDir, cleanup, err := testutil.SetupBundleDir(spec)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer cleanup()

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
		if _, err := Load(rootDir, FullID{ContainerID: shortid}, LoadOpts{}); err != nil {
			t.Errorf("%q should resolve to %q: %v", shortid, longid, err)
		}
	}

	// These should be ambiguous.
	ambiguous := []string{
		"b",
		"ba",
	}
	for _, shortid := range ambiguous {
		if s, err := Load(rootDir, FullID{ContainerID: shortid}, LoadOpts{}); err == nil {
			t.Errorf("%q should be ambiguous, but resolved to %q", shortid, s.ID)
		}
	}
}

func TestGoferExits(t *testing.T) {
	spec := testutil.NewSpecWithArgs("/bin/sleep", "10000")
	conf := testutil.TestConfig(t)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)

	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	// Create and start the container.
	args := Args{
		ID:        testutil.RandomContainerID(),
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
	sandboxProc, err := os.FindProcess(c.Sandbox.Getpid())
	if err != nil {
		t.Fatalf("error finding sandbox process: %v", err)
	}
	if err := sandboxProc.Kill(); err != nil {
		t.Fatalf("error killing sandbox process: %v", err)
	}

	err = blockUntilWaitable(c.GoferPid)
	if err != nil && err != unix.ECHILD {
		t.Errorf("error waiting for gofer to exit: %v", err)
	}
}

func TestRootNotMount(t *testing.T) {
	appSym, err := testutil.FindFile("test/cmd/test_app/test_app")
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

	conf := testutil.TestConfig(t)
	if err := run(spec, conf); err != nil {
		t.Fatalf("error running sandbox: %v", err)
	}
}

func TestUserLog(t *testing.T) {
	app, err := testutil.FindFile("test/cmd/test_app/test_app")
	if err != nil {
		t.Fatal("error finding test_app:", err)
	}

	// sched_rr_get_interval - not implemented in gvisor.
	num := strconv.Itoa(unix.SYS_SCHED_RR_GET_INTERVAL)
	spec := testutil.NewSpecWithArgs(app, "syscall", "--syscall="+num)
	conf := testutil.TestConfig(t)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	dir, err := ioutil.TempDir(testutil.TmpDir(), "user_log_test")
	if err != nil {
		t.Fatalf("error creating tmp dir: %v", err)
	}
	userLog := filepath.Join(dir, "user.log")

	// Create, start and wait for the container.
	args := Args{
		ID:        testutil.RandomContainerID(),
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
	if want := "Unsupported syscall sched_rr_get_interval("; !strings.Contains(string(out), want) {
		t.Errorf("user log file doesn't contain %q, out: %s", want, string(out))
	}
}

func TestWaitOnExitedSandbox(t *testing.T) {
	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			// Run a shell that sleeps for 1 second and then exits with a
			// non-zero code.
			const wantExit = 17
			cmd := fmt.Sprintf("sleep 1; exit %d", wantExit)
			spec := testutil.NewSpecWithArgs("/bin/sh", "-c", cmd)
			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			// Create and Start the container.
			args := Args{
				ID:        testutil.RandomContainerID(),
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
		})
	}
}

func TestDestroyNotStarted(t *testing.T) {
	spec := testutil.NewSpecWithArgs("/bin/sleep", "100")
	conf := testutil.TestConfig(t)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	// Create the container and check that it can be destroyed.
	args := Args{
		ID:        testutil.RandomContainerID(),
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
		conf := testutil.TestConfig(t)
		rootDir, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer cleanup()

		// Create the container and check that it can be destroyed.
		args := Args{
			ID:        testutil.RandomContainerID(),
			Spec:      spec,
			BundleDir: bundleDir,
		}
		c, err := New(conf, args)
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}

		// Container is not thread safe, so load another instance to run in
		// concurrently.
		startCont, err := Load(rootDir, FullID{ContainerID: args.ID}, LoadOpts{})
		if err != nil {
			t.Fatalf("error loading container: %v", err)
		}
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Ignore failures, start can fail if destroy runs first.
			_ = startCont.Start(conf)
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
	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
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
		})
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
	if err := unix.Mount(src, src, "bind", unix.MS_BIND, ""); err != nil {
		t.Fatalf("mount(%q, %q, MS_BIND): %v", dir, srcMnt, err)
	}
	if err := unix.Mount("", src, "", unix.MS_SHARED, ""); err != nil {
		t.Fatalf("mount(%q, MS_SHARED): %v", srcMnt, err)
	}

	spec, conf := sleepSpecConf(t)

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

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
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
	if err := unix.Mount(dir, srcMnt, "bind", unix.MS_BIND, ""); err != nil {
		t.Fatalf("mount(%q, %q, MS_BIND): %v", dir, srcMnt, err)
	}

	// Check that mount didn't propagate to private mount.
	privFile := filepath.Join(priv, "mnt", "file")
	if ws, err := execute(conf, cont, "/usr/bin/test", "!", "-f", privFile); err != nil || ws != 0 {
		t.Fatalf("exec: test ! -f %q, ws: %v, err: %v", privFile, ws, err)
	}

	// Check that mount propagated to slave mount.
	slaveFile := filepath.Join(slave, "mnt", "file")
	if ws, err := execute(conf, cont, "/usr/bin/test", "-f", slaveFile); err != nil || ws != 0 {
		t.Fatalf("exec: test -f %q, ws: %v, err: %v", privFile, ws, err)
	}
}

func TestMountSymlink(t *testing.T) {
	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			dir, err := ioutil.TempDir(testutil.TmpDir(), "mount-symlink")
			if err != nil {
				t.Fatalf("ioutil.TempDir() failed: %v", err)
			}
			defer os.RemoveAll(dir)

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

			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			args := Args{
				ID:        testutil.RandomContainerID(),
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
			if ws, err := execute(conf, cont, "/usr/bin/test", "-f", file); err != nil || ws != 0 {
				t.Fatalf("exec: test -f %q, ws: %v, err: %v", file, ws, err)
			}
		})
	}
}

// Check that --net-raw disables the CAP_NET_RAW capability.
func TestNetRaw(t *testing.T) {
	capNetRaw := strconv.FormatUint(bits.MaskOf64(int(linux.CAP_NET_RAW)), 10)
	app, err := testutil.FindFile("test/cmd/test_app/test_app")
	if err != nil {
		t.Fatal("error finding test_app:", err)
	}

	for _, enableRaw := range []bool{true, false} {
		conf := testutil.TestConfig(t)
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

// TestTTYField checks TTY field returned by container.Processes().
func TestTTYField(t *testing.T) {
	stop := testutil.StartReaper()
	defer stop()

	testApp, err := testutil.FindFile("test/cmd/test_app/test_app")
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
			conf := testutil.TestConfig(t)

			// We will run /bin/sleep, possibly with an open TTY.
			cmd := []string{"/bin/sleep", "10000"}
			if test.useTTY {
				// Run inside the "pty-runner".
				cmd = append([]string{testApp, "pty-runner"}, cmd...)
			}

			spec := testutil.NewSpecWithArgs(cmd...)
			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			// Create and start the container.
			args := Args{
				ID:        testutil.RandomContainerID(),
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

// Test that container can run even when there are corrupt state files in the
// root directiry.
func TestCreateWithCorruptedStateFile(t *testing.T) {
	conf := testutil.TestConfig(t)
	spec := testutil.NewSpecWithArgs("/bin/true")
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	// Create corrupted state file.
	corruptID := testutil.RandomContainerID()
	corruptState := buildPath(conf.RootDir, FullID{SandboxID: corruptID, ContainerID: corruptID}, stateFileExtension)
	if err := ioutil.WriteFile(corruptState, []byte("this{file(is;not[valid.json"), 0777); err != nil {
		t.Fatalf("createCorruptStateFile(): %v", err)
	}
	defer os.Remove(corruptState)

	if _, err := Load(conf.RootDir, FullID{ContainerID: corruptID}, LoadOpts{SkipCheck: true}); err == nil {
		t.Fatalf("loading corrupted state file should have failed")
	}

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
		Attached:  true,
	}
	if ws, err := Run(conf, args); err != nil {
		t.Errorf("running container: %v", err)
	} else if !ws.Exited() || ws.ExitStatus() != 0 {
		t.Errorf("container failed, waitStatus: %v", ws)
	}
}

func TestBindMountByOption(t *testing.T) {
	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			dir, err := ioutil.TempDir(testutil.TmpDir(), "bind-mount")
			spec := testutil.NewSpecWithArgs("/bin/touch", path.Join(dir, "file"))
			if err != nil {
				t.Fatalf("ioutil.TempDir(): %v", err)
			}
			spec.Mounts = append(spec.Mounts, specs.Mount{
				Destination: dir,
				Source:      dir,
				Type:        "none",
				Options:     []string{"rw", "bind"},
			})
			if err := run(spec, conf); err != nil {
				t.Fatalf("error running sandbox: %v", err)
			}
		})
	}
}

// TestRlimits sets limit to number of open files and checks that the limit
// is propagated to the container.
func TestRlimits(t *testing.T) {
	file, err := ioutil.TempFile(testutil.TmpDir(), "ulimit")
	if err != nil {
		t.Fatal(err)
	}
	cmd := fmt.Sprintf("ulimit -n > %q", file.Name())

	spec := testutil.NewSpecWithArgs("sh", "-c", cmd)
	spec.Process.Rlimits = []specs.POSIXRlimit{
		{Type: "RLIMIT_NOFILE", Hard: 1000, Soft: 100},
	}

	conf := testutil.TestConfig(t)
	if err := run(spec, conf); err != nil {
		t.Fatalf("Error running container: %v", err)
	}
	got, err := ioutil.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if want := "100\n"; string(got) != want {
		t.Errorf("ulimit result, got: %q, want: %q", got, want)
	}
}

// TestRlimitsExec sets limit to number of open files and checks that the limit
// is propagated to exec'd processes.
func TestRlimitsExec(t *testing.T) {
	spec, conf := sleepSpecConf(t)
	spec.Process.Rlimits = []specs.POSIXRlimit{
		{Type: "RLIMIT_NOFILE", Hard: 1000, Soft: 100},
	}

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
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

	got, err := executeCombinedOutput(conf, cont, nil, "/bin/sh", "-c", "ulimit -n")
	if err != nil {
		t.Fatal(err)
	}
	if want := "100\n"; string(got) != want {
		t.Errorf("ulimit result, got: %q, want: %q", got, want)
	}
}

// TestUsage checks that usage generates the expected memory usage.
func TestUsage(t *testing.T) {
	spec, conf := sleepSpecConf(t)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}

	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("Creating container: %v", err)
	}
	defer cont.Destroy()

	if err := cont.Start(conf); err != nil {
		t.Fatalf("starting container: %v", err)
	}

	for _, full := range []bool{false, true} {
		m, err := cont.Sandbox.Usage(full)
		if err != nil {
			t.Fatalf("error usage from container: %v", err)
		}
		if m.Mapped == 0 {
			t.Errorf("Usage mapped got zero")
		}
		if m.Total == 0 {
			t.Errorf("Usage total got zero")
		}
		if full {
			if m.System == 0 {
				t.Errorf("Usage system got zero")
			}
			if m.Anonymous == 0 {
				t.Errorf("Usage anonymous got zero")
			}
		}
	}
}

// TestUsageFD checks that usagefd generates the expected memory usage.
func TestUsageFD(t *testing.T) {
	spec, conf := sleepSpecConf(t)

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}

	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("Creating container: %v", err)
	}
	defer cont.Destroy()

	if err := cont.Start(conf); err != nil {
		t.Fatalf("starting container: %v", err)
	}

	m, err := cont.Sandbox.UsageFD()
	if err != nil {
		t.Fatalf("error usageFD from container: %v", err)
	}

	mapped, unknown, total, err := m.Fetch()
	if err != nil {
		t.Fatalf("error Fetch memory usage: %v", err)
	}

	if mapped == 0 {
		t.Errorf("UsageFD Mapped got zero")
	}
	if unknown == 0 {
		t.Errorf("UsageFD unknown got zero")
	}
	if total == 0 {
		t.Errorf("UsageFD total got zero")
	}
}

// TestProfile checks that profiling options generate profiles.
func TestProfile(t *testing.T) {
	// Perform a non-trivial amount of work so we actually capture
	// something in the profiles.
	spec := testutil.NewSpecWithArgs("/bin/bash", "-c", "true")
	conf := testutil.TestConfig(t)
	conf.ProfileEnable = true
	conf.ProfileBlock = filepath.Join(t.TempDir(), "block.pprof")
	conf.ProfileCPU = filepath.Join(t.TempDir(), "cpu.pprof")
	conf.ProfileHeap = filepath.Join(t.TempDir(), "heap.pprof")
	conf.ProfileMutex = filepath.Join(t.TempDir(), "mutex.pprof")
	conf.TraceFile = filepath.Join(t.TempDir(), "trace.out")

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
		Attached:  true,
	}

	_, err = Run(conf, args)
	if err != nil {
		t.Fatalf("Creating container: %v", err)
	}

	// Basic test; simply assert that the profiles are not empty.
	for _, name := range []string{conf.ProfileBlock, conf.ProfileCPU, conf.ProfileHeap, conf.ProfileMutex, conf.TraceFile} {
		fi, err := os.Stat(name)
		if err != nil {
			t.Fatalf("Unable to stat profile file %s: %v", name, err)
		}
		if fi.Size() == 0 {
			t.Errorf("Profile file %s is empty: %+v", name, fi)
		}
	}
}

// TestSaveSystemdCgroup emulates a sandbox saving while configured with the
// systemd cgroup driver.
func TestSaveSystemdCgroup(t *testing.T) {
	spec, conf := sleepSpecConf(t)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	// Create and start the container.
	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()

	cont.CompatCgroup = cgroup.CgroupJSON{Cgroup: cgroup.CreateMockSystemdCgroup()}
	if err := cont.Saver.lock(BlockAcquire); err != nil {
		t.Fatalf("cannot lock container metadata file: %v", err)
	}
	if err := cont.saveLocked(); err != nil {
		t.Fatalf("error saving cgroup: %v", err)
	}
	cont.Saver.unlock()
	loadCont := Container{}
	cont.Saver.load(&loadCont, LoadOpts{})
	if !reflect.DeepEqual(cont.CompatCgroup, loadCont.CompatCgroup) {
		t.Errorf("CompatCgroup not properly saved: want %v, got %v", cont.CompatCgroup, loadCont.CompatCgroup)
	}
}

// TestSandboxCommunicationUnshare checks that communication with sandboxes do
// not require being in the same network namespace. This is required to allow
// Kubernetes daemonsets/containers to communicate with sandboxes without the
// need to join the host network namespaces.
func TestSandboxCommunicationUnshare(t *testing.T) {
	spec, conf := sleepSpecConf(t)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}

	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("Creating container: %v", err)
	}
	defer cont.Destroy()

	if err := cont.Start(conf); err != nil {
		t.Fatalf("starting container: %v", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unix.Unshare(): %v", err)
	}

	// Send a simple command to test that the sandbox can be reached.
	if err := cont.SignalContainer(0, true); err != nil {
		t.Errorf("SignalContainer(): %v", err)
	}
}

// writeAndReadFromPipe writes the bytes to the write end of the pipe, then
// reads from the read end and returns the result.
func writeAndReadFromPipe(write, read *os.File, msg string) (string, error) {
	// Write the message to be read by the guest.
	if _, err := io.StringWriter(write).WriteString(msg); err != nil {
		return "", fmt.Errorf("failed to write message to pipe: %w", err)
	}
	write.Close()

	// Read and return the message.
	response, err := io.ReadAll(read)
	if err != nil {
		return "", fmt.Errorf("failed to read from pipe: %w", err)
	}
	read.Close()

	return string(response), nil
}

func createPipes() (*os.File, *os.File, *os.File, *os.File, func(), error) {
	// This is the first pipe which the host writes to and the guest reads
	// from.
	guestRead, hostWrite, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// This is the second pipe which the guest writes to and the host reads
	// from.
	hostRead, guestWrite, err := os.Pipe()
	if err != nil {
		guestRead.Close()
		hostWrite.Close()
		return nil, nil, nil, nil, nil, err
	}

	cleanup := func() {
		guestRead.Close()
		hostWrite.Close()
		hostRead.Close()
		guestWrite.Close()
	}

	return guestRead, hostWrite, hostRead, guestWrite, cleanup, nil
}

// TestFDPassingRun checks that file descriptors passed into a new container
// work as expected.
func TestFDPassingRun(t *testing.T) {
	guestRead, hostWrite, hostRead, guestWrite, cleanup, err := createPipes()
	if err != nil {
		t.Fatalf("error creating pipes: %v", err)
	}
	defer cleanup()

	// In the guest, read from the host and write the result back to the host.
	conf := testutil.TestConfig(t)
	cmd := fmt.Sprintf("cat /proc/self/fd/%d > /proc/self/fd/%d", int(guestRead.Fd()), int(guestWrite.Fd()))
	spec := testutil.NewSpecWithArgs("bash", "-c", cmd)

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
		PassFiles: map[int]*os.File{
			int(guestRead.Fd()):  guestRead,
			int(guestWrite.Fd()): guestWrite,
		},
	}

	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("Creating container: %v", err)
	}
	defer cont.Destroy()

	if err := cont.Start(conf); err != nil {
		t.Fatalf("starting container: %v", err)
	}

	// We close guestWrite here because it has been passed into the container.
	// If we do not close it, we will never see an EOF.
	guestWrite.Close()

	msg := "hello"
	got, err := writeAndReadFromPipe(hostWrite, hostRead, msg)
	if err != nil {
		t.Fatal(err)
	}
	if got != msg {
		t.Errorf("got message %q, want %q", got, msg)
	}
}

// TestFDPassingExec checks that file descriptors passed into an already
// running container work as expected.
func TestFDPassingExec(t *testing.T) {
	guestRead, hostWrite, hostRead, guestWrite, cleanup, err := createPipes()
	if err != nil {
		t.Fatalf("error creating pipes: %v", err)
	}
	defer cleanup()

	conf := testutil.TestConfig(t)

	// We just sleep here because we want to test file descriptor passing
	// inside a process executed inside an already running container.
	spec := testutil.NewSpecWithArgs("bash", "-c", "sleep infinity")

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}

	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("Creating container: %v", err)
	}
	defer cont.Destroy()

	if err := cont.Start(conf); err != nil {
		t.Fatalf("starting container: %v", err)
	}

	// Prepare executing a command in the running container.
	cmd := fmt.Sprintf("cat /proc/self/fd/%d > /proc/self/fd/%d", int(guestRead.Fd()), int(guestWrite.Fd()))
	execArgs := &control.ExecArgs{
		Argv: []string{"/bin/bash", "-c", cmd},
		FilePayload: control.NewFilePayload(map[int]*os.File{
			int(guestRead.Fd()):  guestRead,
			int(guestWrite.Fd()): guestWrite,
		}, nil),
	}

	if _, err = cont.Execute(conf, execArgs); err != nil {
		t.Fatalf("Failed to execute command: %v", err)
	}

	// We close guestWrite here because it has been passed into the container.
	// If we do not close it, we will never see an EOF.
	guestWrite.Close()

	msg := "hello"
	got, err := writeAndReadFromPipe(hostWrite, hostRead, msg)
	if err != nil {
		t.Fatal(err)
	}
	if got != msg {
		t.Errorf("got message %q, want %q", got, msg)
	}
}

// findInPath finds a filename in the PATH environment variable.
func findInPath(filename string) string {
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		fullPath := filepath.Join(dir, filename)
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath
		}
	}
	return ""
}

// TestExecFDRun checks that an executable from the host can be started inside
// a container.
func TestExecFDRun(t *testing.T) {
	// In the guest, read from the host and write the result back to the host.
	conf := testutil.TestConfig(t)
	// Note that we do not supply the name or path of the echo binary here.
	// Thus, the guest does not know the binary path or name either.
	// argv[0] inside echo is "can be anything".
	spec := testutil.NewSpecWithArgs("can be anything", "hello world")

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	// Find the echo binary on the host.
	echoPath := findInPath("echo")
	if echoPath == "" {
		t.Fatalf("failed to find echo executable in PATH")
	}

	// Open the echo binary as a file.
	echoFile, err := os.Open(echoPath)
	if err != nil {
		t.Fatalf("opening echo binary: %v", err)
	}
	defer echoFile.Close()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	defer r.Close()

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
		PassFiles: map[int]*os.File{
			0: os.Stdin, 1: w, 2: w,
		},
		ExecFile: echoFile,
	}

	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("Creating container: %v", err)
	}
	defer cont.Destroy()

	if err := cont.Start(conf); err != nil {
		t.Fatalf("starting container: %v", err)
	}

	w.Close()

	got, err := io.ReadAll(r)
	if err != nil {
		t.Errorf("reading container output: %v", err)
	}
	if want := "hello world\n"; string(got) != want {
		t.Errorf("got message %q, want %q", got, want)
	}
}

// TestExecFDExec checks that an executable from the host can be started from a
// file descriptor inside an already running container.
func TestExecFDExec(t *testing.T) {
	conf := testutil.TestConfig(t)

	// We just sleep here because we want to test execution in an already
	// running container.
	spec := testutil.NewSpecWithArgs("bash", "-c", "sleep infinity")

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}

	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("Creating container: %v", err)
	}
	defer cont.Destroy()

	if err := cont.Start(conf); err != nil {
		t.Fatalf("starting container: %v", err)
	}

	// Find the echo binary on the host.
	echoPath := findInPath("echo")
	if echoPath == "" {
		t.Fatalf("failed to find echo executable in PATH")
	}

	// Open the echo binary as a file.
	echoFile, err := os.Open(echoPath)
	if err != nil {
		t.Fatalf("opening echo binary: %v", err)
	}
	defer echoFile.Close()

	// Note that we do not supply the name or path of the echo binary here.
	// Thus, the guest does not know the binary path or name either.
	// argv[0] inside echo is "can be anything".
	got, err := executeCombinedOutput(conf, cont, echoFile, "can be anything", "hello world")
	if err != nil {
		t.Fatal(err)
	}
	if want := "hello world\n"; string(got) != want {
		t.Errorf("echo result, got: %q, want: %q", got, want)
	}
}
