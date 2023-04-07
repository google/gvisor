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

// Binary syscall_test_runner runs the syscall test suites in gVisor
// containers and on the host platform.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/test/runner/gtest"
	"gvisor.dev/gvisor/test/trace/config"
	"gvisor.dev/gvisor/test/uds"
)

var (
	debug              = flag.Bool("debug", false, "enable debug logs")
	oneSandbox         = flag.Bool("one-sandbox", false, "run all test cases in one sandbox")
	strace             = flag.Bool("strace", false, "enable strace logs")
	platform           = flag.String("platform", "ptrace", "platform to run on")
	platformSupport    = flag.String("platform-support", "", "String passed to the test as GVISOR_PLATFORM_SUPPORT environment variable. Used to determine which syscall tests are expected to work with the current platform.")
	network            = flag.String("network", "none", "network stack to run on (sandbox, host, none)")
	useTmpfs           = flag.Bool("use-tmpfs", false, "mounts tmpfs for /tmp")
	fusefs             = flag.Bool("fusefs", false, "mounts a fusefs for /tmp")
	fileAccess         = flag.String("file-access", "exclusive", "mounts root in exclusive or shared mode")
	overlay            = flag.Bool("overlay", false, "wrap filesystem mounts with writable tmpfs overlay")
	container          = flag.Bool("container", false, "run tests in their own namespaces (user ns, network ns, etc), pretending to be root. Implicitly enabled if network=host, or if using network namespaces")
	setupContainerPath = flag.String("setup-container", "", "path to setup_container binary (for use with --container)")
	trace              = flag.Bool("trace", false, "enables all trace points")

	addHostUDS       = flag.Bool("add-host-uds", false, "expose a tree of UDS to test communication with the host")
	addHostConnector = flag.Bool("add-host-connector", false, "create goroutines that connect to bound UDS that will be created by sandbox")
	addHostFIFO      = flag.Bool("add-host-fifo", false, "expose a tree of FIFO to test communication with the host")
	ioUring          = flag.Bool("iouring", false, "Enables IO_URING API for asynchronous I/O")
	// TODO(gvisor.dev/issue/4572): properly support leak checking for runsc, and
	// set to true as the default for the test runner.
	leakCheck  = flag.Bool("leak-check", false, "check for reference leaks")
	waitForPid = flag.Duration("delay-for-debugger", 0, "Print out the sandbox PID and wait for the specified duration to start the test. This is useful for attaching a debugger to the runsc-sandbox process.")
)

const (
	// Environment variable used by platform_util.cc to determine platform capabilities.
	platformSupportEnvVar = "GVISOR_PLATFORM_SUPPORT"
)

// getSetupContainerPath returns the path to the setup_container binary.
func getSetupContainerPath() string {
	if *setupContainerPath != "" {
		return *setupContainerPath
	}
	setupContainer, err := testutil.FindFile("test/runner/setup_container/setup_container")
	if err != nil {
		fatalf("cannot find setup_container: %v", err)
	}
	return setupContainer
}

// runTestCaseNative runs the test case directly on the host machine.
func runTestCaseNative(testBin string, tc *gtest.TestCase, args []string, t *testing.T) {
	// These tests might be running in parallel, so make sure they have a
	// unique test temp dir.
	tmpDir, err := ioutil.TempDir(testutil.TmpDir(), "")
	if err != nil {
		t.Fatalf("could not create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Replace TEST_TMPDIR in the current environment with something
	// unique.
	env := os.Environ()
	newEnvVar := "TEST_TMPDIR=" + tmpDir
	var found bool
	for i, kv := range env {
		if strings.HasPrefix(kv, "TEST_TMPDIR=") {
			env[i] = newEnvVar
			found = true
			break
		}
	}
	if !found {
		env = append(env, newEnvVar)
	}
	// Remove shard env variables so that the gunit binary does not try to
	// interpret them.
	env = filterEnv(env, []string{"TEST_SHARD_INDEX", "TEST_TOTAL_SHARDS", "GTEST_SHARD_INDEX", "GTEST_TOTAL_SHARDS"})

	if *addHostUDS {
		socketDir, cleanup, err := uds.CreateBoundUDSTree("/tmp")
		if err != nil {
			t.Fatalf("failed to create socket tree: %v", err)
		}
		defer cleanup()

		env = append(env, "TEST_UDS_TREE="+socketDir)
		// On Linux, the concept of "attach" location doesn't exist.
		// Just pass the same path to make these tests identical.
		env = append(env, "TEST_UDS_ATTACH_TREE="+socketDir)
	}

	if *addHostConnector {
		connectorDir, cleanup, err := uds.CreateSocketConnectors("/tmp")
		if err != nil {
			t.Fatalf("failed to create socket connectors: %v", err)
		}
		defer cleanup()

		env = append(env, "TEST_CONNECTOR_TREE="+connectorDir)
	}

	if *addHostFIFO {
		pipeDir, cleanup, err := uds.CreateFifoTree("/tmp")
		if err != nil {
			t.Fatalf("failed to create pipe tree: %v", err)
		}
		defer cleanup()

		env = append(env, "TEST_FIFO_TREE="+pipeDir)
		// On Linux, the concept of "attach" location doesn't exist.
		// Just pass the same path to make these tests identical.
		env = append(env, "TEST_FIFO_ATTACH_TREE="+pipeDir)
	}

	if *platformSupport != "" {
		env = append(env, fmt.Sprintf("%s=%s", platformSupportEnvVar, *platformSupport))
	}

	if args == nil {
		args = tc.Args()
	}

	cmd := exec.Command(testBin, args...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &unix.SysProcAttr{}

	if specutils.HasCapabilities(capability.CAP_SYS_ADMIN) {
		cmd.SysProcAttr.Cloneflags |= unix.CLONE_NEWUTS
	}

	if specutils.HasCapabilities(capability.CAP_NET_ADMIN) {
		cmd.SysProcAttr.Cloneflags |= unix.CLONE_NEWNET
	}

	if *container || (cmd.SysProcAttr.Cloneflags&unix.CLONE_NEWNET != 0) {
		// setup_container takes in its target argv as positional arguments.
		cmd.Path = getSetupContainerPath()
		cmd.Args = append([]string{cmd.Path}, cmd.Args...)
		cmd.SysProcAttr.Cloneflags |= unix.CLONE_NEWUSER | unix.CLONE_NEWNET | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS
		// Set current user/group as root inside the namespace.
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		}
		cmd.SysProcAttr.GidMappingsEnableSetgroups = false
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: 0,
			Gid: 0,
		}
	}

	if err := cmd.Run(); err != nil {
		ws := err.(*exec.ExitError).Sys().(syscall.WaitStatus)
		t.Errorf("test %q exited with status %d, want 0", tc.FullName(), ws.ExitStatus())
	}
}

// runRunsc runs spec in runsc in a standard test configuration.
//
// runsc logs will be saved to a path in TEST_UNDECLARED_OUTPUTS_DIR.
//
// Returns an error if the sandboxed application exits non-zero.
func runRunsc(tc *gtest.TestCase, spec *specs.Spec) error {
	bundleDir, cleanup, err := testutil.SetupBundleDir(spec)
	if err != nil {
		return fmt.Errorf("SetupBundleDir failed: %v", err)
	}
	defer cleanup()

	rootDir, cleanup, err := testutil.SetupRootDir()
	if err != nil {
		return fmt.Errorf("SetupRootDir failed: %v", err)
	}
	defer cleanup()

	name := tc.FullName()
	id := testutil.RandomContainerID()
	log.Infof("Running test %q in container %q", name, id)
	specutils.LogSpecDebug(spec, false)

	args := []string{
		"-root", rootDir,
		"-network", *network,
		"-log-format=text",
		"-TESTONLY-unsafe-nonroot=true",
		"-TESTONLY-allow-packet-endpoint-write=true",
		fmt.Sprintf("-panic-signal=%d", unix.SIGTERM),
		fmt.Sprintf("-iouring=%t", *ioUring),
		"-watchdog-action=panic",
		"-platform", *platform,
		"-file-access", *fileAccess,
		"-gvisor-gro=200000ns",
	}

	if *network == "host" && !specutils.HasCapabilities(capability.CAP_NET_RAW) {
		log.Warningf("Testing with network=host but host does not have CAP_NET_RAW. Raw socket support will be disabled.")
	} else {
		args = append(args, "-net-raw")
	}
	if *overlay {
		args = append(args, "-overlay2=all:dir=/tmp")
	} else {
		args = append(args, "-overlay2=none")
	}
	if *debug {
		args = append(args, "-debug", "-log-packets=true")
	}
	if *strace {
		args = append(args, "-strace")
	}
	if *addHostUDS {
		args = append(args, "-host-uds=open")
	}
	if *addHostConnector {
		args = append(args, "-host-uds=create")
	}
	if *addHostFIFO {
		args = append(args, "-host-fifo=open")
	}
	if *leakCheck {
		args = append(args, "-ref-leak-mode=log-names")
	}
	if *trace {
		flag, err := enableAllTraces(rootDir)
		if err != nil {
			return fmt.Errorf("enabling all traces: %w", err)
		}
		log.Infof("Enabling all trace points: %s", flag)
		args = append(args, flag)
	}

	testLogDir := ""
	if undeclaredOutputsDir, ok := unix.Getenv("TEST_UNDECLARED_OUTPUTS_DIR"); ok {
		// Create log directory dedicated for this test.
		testLogDir = filepath.Join(undeclaredOutputsDir, strings.Replace(name, "/", "_", -1))
		if err := os.MkdirAll(testLogDir, 0755); err != nil {
			return fmt.Errorf("could not create test dir: %v", err)
		}
		debugLogDir, err := ioutil.TempDir(testLogDir, "runsc")
		if err != nil {
			return fmt.Errorf("could not create temp dir: %v", err)
		}
		debugLogDir += "/"
		log.Infof("runsc logs: %s", debugLogDir)
		args = append(args, "-debug-log", debugLogDir)
		args = append(args, "-coverage-report", debugLogDir)

		// Default -log sends messages to stderr which makes reading the test log
		// difficult. Instead, drop them when debug log is enabled given it's a
		// better place for these messages.
		args = append(args, "-log=/dev/null")
	}

	// Current process doesn't have CAP_SYS_ADMIN, create user namespace and run
	// as root inside that namespace to get it.
	sysProcAttr := &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		// Set current user/group as root inside the namespace.
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		Credential: &syscall.Credential{
			Uid: 0,
			Gid: 0,
		},
	}
	var cmdArgs []string
	if *waitForPid != 0 {
		createArgs := append(args, "create", "-pid-file", filepath.Join(testLogDir, "pid"), "--bundle", bundleDir, id)
		defer os.Remove(filepath.Join(testLogDir, "pid"))
		createCmd := exec.Command(specutils.ExePath, createArgs...)
		createCmd.SysProcAttr = sysProcAttr
		createCmd.Stdout = os.Stdout
		createCmd.Stderr = os.Stderr
		if err := createCmd.Run(); err != nil {
			return fmt.Errorf("could not create sandbox: %v", err)
		}

		sandboxPidBytes, err := os.ReadFile(filepath.Join(testLogDir, "pid"))
		if err != nil {
			return fmt.Errorf("could not read pid file: %v", err)
		}
		log.Infof("Sandbox process ID is %s. You can attach to it from a debugger of your choice.", sandboxPidBytes)
		log.Infof("For example, with Delve you can call: $ dlv attach %s", sandboxPidBytes)
		log.Infof("The test will automatically start after %s.", *waitForPid)
		log.Infof("You may also signal the test process to start the test immediately: $ kill -SIGUSR1 %d", os.Getpid())

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, unix.SIGUSR1)
		select {
		case <-sigCh:
		case <-time.After(*waitForPid):
		}
		signal.Reset(unix.SIGUSR1)

		cmdArgs = append(args, "start", id)
	} else {
		cmdArgs = append(args, "run", "--bundle", bundleDir, id)
	}
	cmd := exec.Command(specutils.ExePath, cmdArgs...)
	cmd.SysProcAttr = sysProcAttr
	if *container || *network == "host" || (cmd.SysProcAttr.Cloneflags&unix.CLONE_NEWNET != 0) {
		cmd.SysProcAttr.Cloneflags |= unix.CLONE_NEWNET
		cmd.Path = getSetupContainerPath()
		cmd.Args = append([]string{cmd.Path}, cmd.Args...)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	sig := make(chan os.Signal, 1)
	defer close(sig)
	signal.Notify(sig, unix.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		s, ok := <-sig
		if !ok {
			return
		}
		log.Warningf("%s: Got signal: %v", name, s)
		done := make(chan bool, 1)
		dArgs := append([]string{}, args...)
		dArgs = append(dArgs, "debug", "--stacks", id)
		go func(dArgs []string) {
			debug := exec.Command(specutils.ExePath, dArgs...)
			debug.Stdout = os.Stdout
			debug.Stderr = os.Stderr
			debug.Run()
			done <- true
		}(dArgs)

		timeout := time.After(3 * time.Second)
		select {
		case <-timeout:
			log.Infof("runsc debug --stacks is timeouted")
		case <-done:
		}

		log.Warningf("Send SIGTERM to the sandbox process")
		dArgs = append(args, "debug",
			fmt.Sprintf("--signal=%d", unix.SIGTERM),
			id)
		signal := exec.Command(specutils.ExePath, dArgs...)
		signal.Stdout = os.Stdout
		signal.Stderr = os.Stderr
		signal.Run()
	}()

	err = cmd.Run()
	if *waitForPid != 0 {
		if err != nil {
			return fmt.Errorf("could not start container: %v", err)
		}
		waitArgs := append(args, "wait", id)
		waitCmd := exec.Command(specutils.ExePath, waitArgs...)
		waitCmd.SysProcAttr = sysProcAttr
		waitCmd.Stdout = os.Stdout
		waitCmd.Stderr = os.Stderr
		err = waitCmd.Run()
	}
	if err == nil && len(testLogDir) > 0 {
		// If the test passed, then we erase the log directory. This speeds up
		// uploading logs in continuous integration & saves on disk space.
		os.RemoveAll(testLogDir)
	}

	return err
}

// setupHostUDSTree updates the spec to expose a UDS files tree for testing
// communication with the host.
func setupHostUDSTree(spec *specs.Spec) (cleanup func(), err error) {
	socketDir, cleanup, err := uds.CreateBoundUDSTree("/tmp")
	if err != nil {
		return nil, fmt.Errorf("failed to create socket tree: %v", err)
	}

	// Standard access to entire tree.
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/tmp/sockets",
		Source:      socketDir,
		Type:        "bind",
	})

	// Individial attach points for each socket to test mounts that attach
	// directly to the sockets.
	for _, protocol := range []string{"stream", "seqpacket"} {
		for _, name := range []string{"echo", "nonlistening"} {
			spec.Mounts = append(spec.Mounts, specs.Mount{
				Destination: filepath.Join("/tmp/sockets-attach", protocol, name),
				Source:      filepath.Join(socketDir, protocol, name),
				Type:        "bind",
			})
		}
	}
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/tmp/sockets-attach/dgram/null",
		Source:      filepath.Join(socketDir, "dgram/null"),
		Type:        "bind",
	})

	spec.Process.Env = append(spec.Process.Env, "TEST_UDS_TREE=/tmp/sockets")
	spec.Process.Env = append(spec.Process.Env, "TEST_UDS_ATTACH_TREE=/tmp/sockets-attach")

	return cleanup, nil
}

// setupHostFifoTree starts goroutines that will attempt to connect to sockets
// in a directory that will be bind mounted into the container.
func setupHostConnectorTree(spec *specs.Spec) (cleanup func(), err error) {
	connectorDir, cleanup, err := uds.CreateSocketConnectors("/tmp")
	if err != nil {
		return nil, fmt.Errorf("failed to create connector tree: %v", err)
	}

	// Standard access to entire tree.
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/tmp/connectors",
		Source:      connectorDir,
		Type:        "bind",
	})
	// We can not create individual attach points for sockets that have not been
	// created yet.
	spec.Process.Env = append(spec.Process.Env, "TEST_CONNECTOR_TREE=/tmp/connectors")
	return cleanup, nil
}

// setupHostFifoTree updates the spec to expose FIFO file tree for testing
// communication with the host.
func setupHostFifoTree(spec *specs.Spec) (cleanup func(), err error) {
	fifoDir, cleanup, err := uds.CreateFifoTree("/tmp")
	if err != nil {
		return nil, fmt.Errorf("failed to create FIFO tree: %v", err)
	}

	// Standard access to entire tree.
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/tmp/pipes",
		Source:      fifoDir,
		Type:        "bind",
	})

	// Individual attach points for each pipe to test mounts that attach
	// directly to the pipe.
	for _, name := range []string{"in", "out"} {
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: filepath.Join("/tmp/pipes-attach", name),
			Source:      filepath.Join(fifoDir, name),
			Type:        "bind",
		})
	}

	spec.Process.Env = append(spec.Process.Env, "TEST_FIFO_TREE=/tmp/pipes")
	spec.Process.Env = append(spec.Process.Env, "TEST_FIFO_ATTACH_TREE=/tmp/pipes-attach")

	return cleanup, nil
}

// runsTestCaseRunsc runs the test case in runsc.
func runTestCaseRunsc(testBin string, tc *gtest.TestCase, args []string, t *testing.T) {
	// Run a new container with the test executable and filter for the
	// given test suite and name.
	if args == nil {
		args = tc.Args()
	}
	var spec *specs.Spec
	if *fusefs {
		fuseServer, err := testutil.FindFile("test/runner/fuse/fuse")
		if err != nil {
			fatalf("cannot find fuse: %v", err)
		}
		spec = testutil.NewSpecWithArgs(append([]string{fuseServer, testBin}, args...)...)
	} else {
		spec = testutil.NewSpecWithArgs(append([]string{testBin}, args...)...)
	}
	// Mark the root as writeable, as some tests attempt to
	// write to the rootfs, and expect EACCES, not EROFS.
	spec.Root.Readonly = false

	// Test spec comes with pre-defined mounts that we don't want. Reset it.
	spec.Mounts = nil
	testTmpDir := "/tmp"
	if *useTmpfs {
		// Forces '/tmp' to be mounted as tmpfs, otherwise test that rely on
		// features only available in gVisor's internal tmpfs may fail.
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: "/tmp",
			Type:        "tmpfs",
		})
	} else {
		// Use a gofer-backed directory as '/tmp'.
		//
		// Tests might be running in parallel, so make sure each has a
		// unique test temp dir.
		//
		// Some tests (e.g., sticky) access this mount from other
		// users, so make sure it is world-accessible.
		tmpDir, err := ioutil.TempDir(testutil.TmpDir(), "")
		if err != nil {
			t.Fatalf("could not create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		if err := os.Chmod(tmpDir, 0777); err != nil {
			t.Fatalf("could not chmod temp dir: %v", err)
		}

		// "/tmp" is not replaced with a tmpfs mount inside the sandbox
		// when it's not empty. This ensures that testTmpDir uses gofer
		// in exclusive mode.
		testTmpDir = tmpDir
		if *fileAccess == "shared" {
			// All external mounts except the root mount are shared.
			spec.Mounts = append(spec.Mounts, specs.Mount{
				Type:        "bind",
				Destination: "/tmp",
				Source:      tmpDir,
			})
			testTmpDir = "/tmp"
		}
	}
	if *fusefs {
		// In fuse tests, the fuse server forwards all filesystem ops from /tmp
		// to /fuse.
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: "/fuse",
			Type:        "tmpfs",
		})
	}
	if *network == "host" {
		// If host does not have CAP_NET_ADMIN or CAP_NET_RAW, then we
		// must drop those caps inside the sandbox, since we will not
		// be able to perform those operations with hostinet.
		if !specutils.HasCapabilities(capability.CAP_NET_ADMIN) {
			log.Warningf("Running with network=host, but host does not have CAP_NET_ADMIN. Dropping this capability inside the sandbox.")
			specutils.DropCapability(spec.Process.Capabilities, "CAP_NET_ADMIN")

		}
		if !specutils.HasCapabilities(capability.CAP_NET_RAW) {
			log.Warningf("Running with network=host, but host does not have CAP_NET_RAW. Dropping this capability inside the sandbox.")
			specutils.DropCapability(spec.Process.Capabilities, "CAP_NET_RAW")
		}
	}

	// Set environment variables that indicate we are running in gVisor with
	// the given platform, network, and filesystem stack.
	const (
		platformVar = "TEST_ON_GVISOR"
		networkVar  = "GVISOR_NETWORK"
		ioUringVar  = "IOURING_ENABLED"
		fuseVar     = "GVISOR_FUSE_TEST"
	)
	env := append(os.Environ(), platformVar+"="+*platform, networkVar+"="+*network)
	if *platformSupport != "" {
		env = append(env, fmt.Sprintf("%s=%s", platformSupportEnvVar, *platformSupport))
	}
	if *ioUring {
		env = append(env, ioUringVar+"=TRUE")
	} else {
		env = append(env, ioUringVar+"=FALSE")
	}
	if *fusefs {
		env = append(env, fuseVar+"=TRUE")
	} else {
		env = append(env, fuseVar+"=FALSE")
	}

	// Remove shard env variables so that the gunit binary does not try to
	// interpret them.
	env = filterEnv(env, []string{"TEST_SHARD_INDEX", "TEST_TOTAL_SHARDS", "GTEST_SHARD_INDEX", "GTEST_TOTAL_SHARDS"})

	// Set TEST_TMPDIR to /tmp, as some of the syscall tests require it to
	// be backed by tmpfs.
	env = filterEnv(env, []string{"TEST_TMPDIR"})
	env = append(env, fmt.Sprintf("TEST_TMPDIR=%s", testTmpDir))

	spec.Process.Env = env

	if *addHostUDS {
		cleanup, err := setupHostUDSTree(spec)
		if err != nil {
			t.Fatalf("error creating UDS tree: %v", err)
		}
		defer cleanup()
	}
	if *addHostConnector {
		cleanup, err := setupHostConnectorTree(spec)
		if err != nil {
			t.Fatalf("error creating connector tree: %v", err)
		}
		defer cleanup()
	}
	if *addHostFIFO {
		cleanup, err := setupHostFifoTree(spec)
		if err != nil {
			t.Fatalf("error creating FIFO tree: %v", err)
		}
		defer cleanup()
	}

	if err := runRunsc(tc, spec); err != nil {
		t.Errorf("test %q failed with error %v, want nil", tc.FullName(), err)
	}
}

// filterEnv returns an environment with the excluded variables removed.
func filterEnv(env, exclude []string) []string {
	var out []string
	for _, kv := range env {
		ok := true
		for _, k := range exclude {
			if strings.HasPrefix(kv, k+"=") {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, kv)
		}
	}
	return out
}

func fatalf(s string, args ...any) {
	fmt.Fprintf(os.Stderr, s+"\n", args...)
	os.Exit(1)
}

func matchString(a, b string) (bool, error) {
	return a == b, nil
}

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		fatalf("test must be provided")
	}
	testBin := flag.Args()[0] // Only argument.

	log.SetLevel(log.Info)
	if *debug {
		log.SetLevel(log.Debug)
	}

	if *platform != "native" {
		if err := testutil.ConfigureExePath(); err != nil {
			panic(err.Error())
		}
	}

	// Make sure stdout and stderr are opened with O_APPEND, otherwise logs
	// from outside the sandbox can (and will) stomp on logs from inside
	// the sandbox.
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		if err != nil {
			fatalf("error getting file flags for %v: %v", f, err)
		}
		if flags&unix.O_APPEND == 0 {
			flags |= unix.O_APPEND
			if _, err := unix.FcntlInt(f.Fd(), unix.F_SETFL, flags); err != nil {
				fatalf("error setting file flags for %v: %v", f, err)
			}
		}
	}

	// Get all test cases in each binary.
	testCases, err := gtest.ParseTestCases(testBin, true)
	if err != nil {
		fatalf("ParseTestCases(%q) failed: %v", testBin, err)
	}

	// Get subset of tests corresponding to shard.
	indices, err := testutil.TestIndicesForShard(len(testCases))
	if err != nil {
		fatalf("TestsForShard() failed: %v", err)
	}

	// Resolve the absolute path for the binary.
	testBin, err = filepath.Abs(testBin)
	if err != nil {
		fatalf("Abs() failed: %v", err)
	}

	var tests []testing.InternalTest
	if *oneSandbox {
		tc := gtest.TestCase{
			Suite: "main",
			Name:  "test",
		}

		tests = append(tests, testing.InternalTest{
			Name: fmt.Sprintf("%s_%s", tc.Suite, tc.Name),
			F: func(t *testing.T) {
				args := gtest.BuildTestArgs(indices, testCases)
				if *platform == "native" {
					// Run the test case on host.
					runTestCaseNative(testBin, &tc, args, t)
				} else {
					// Run the test case in runsc.
					runTestCaseRunsc(testBin, &tc, args, t)
				}
			},
		})
	} else {
		// Run the tests.
		for _, tci := range indices {
			// Capture tc.
			tc := testCases[tci]
			tests = append(tests, testing.InternalTest{
				Name: fmt.Sprintf("%s_%s", tc.Suite, tc.Name),
				F: func(t *testing.T) {
					if *platform == "native" {
						// Run the test case on host.
						runTestCaseNative(testBin, &tc, nil, t)
					} else {
						// Run the test case in runsc.
						runTestCaseRunsc(testBin, &tc, nil, t)
					}
				},
			})
		}
	}

	testing.Main(matchString, tests, nil, nil)
}

func enableAllTraces(dir string) (string, error) {
	builder := config.Builder{}
	if err := builder.LoadAllPoints(specutils.ExePath); err != nil {
		return "", err
	}
	builder.AddSink(seccheck.SinkConfig{
		Name: "null",
	})
	path := filepath.Join(dir, "pod_init.json")
	cfgFile, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer cfgFile.Close()

	if err := builder.WriteInitConfig(cfgFile); err != nil {
		return "", fmt.Errorf("writing config file: %w", err)
	}
	return "--pod-init-config=" + path, nil
}
