// Copyright 2018 Google LLC
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

// Package testutil contains utility functions for runsc tests.
package testutil

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/syndtr/gocapability/capability"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

// RaceEnabled is set to true if it was built with '--race' option.
var RaceEnabled = false

// TmpDir returns the absolute path to a writable directory that can be used as
// scratch by the test.
func TmpDir() string {
	dir := os.Getenv("TEST_TMPDIR")
	if dir == "" {
		dir = "/tmp"
	}
	return dir
}

// ConfigureExePath configures the executable for runsc in the test environment.
func ConfigureExePath() error {
	path, err := FindFile("runsc/runsc")
	if err != nil {
		return err
	}
	specutils.ExePath = path
	return nil
}

// FindFile searchs for a file inside the test run environment. It returns the
// full path to the file. It fails if none or more than one file is found.
func FindFile(path string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// The test root is demarcated by a path element called "__main__". Search for
	// it backwards from the working directory.
	root := wd
	for {
		dir, name := filepath.Split(root)
		if name == "__main__" {
			break
		}
		if len(dir) == 0 {
			return "", fmt.Errorf("directory __main__ not found in %q", wd)
		}
		// Remove ending slash to loop around.
		root = dir[:len(dir)-1]
	}

	// bazel adds the build type to the directory structure. Since I don't want
	// to guess what build type it's, just place '*' to match anything.
	//
	// The pattern goes like: /test-path/__main__/directories/*/file.
	pattern := filepath.Join(root, filepath.Dir(path), "*", filepath.Base(path))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("error globbing %q: %v", pattern, err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("file %q not found", path)
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("more than one match found for %q: %s", path, matches)
	}
	return matches[0], nil
}

// TestConfig returns the default configuration to use in tests. Note that
// 'RootDir' must be set by caller if required.
func TestConfig() *boot.Config {
	return &boot.Config{
		Debug:      true,
		LogFormat:  "text",
		LogPackets: true,
		Network:    boot.NetworkNone,
		Strace:     true,
		FileAccess: boot.FileAccessExclusive,
		TestOnlyAllowRunAsCurrentUserWithoutChroot: true,
	}
}

// TestConfigWithRoot returns the default configuration to use in tests.
func TestConfigWithRoot(rootDir string) *boot.Config {
	conf := TestConfig()
	conf.RootDir = rootDir
	return conf
}

// NewSpecWithArgs creates a simple spec with the given args suitable for use
// in tests.
func NewSpecWithArgs(args ...string) *specs.Spec {
	return &specs.Spec{
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
		Mounts: []specs.Mount{
			// Root is readonly, but many tests want to write to tmpdir.
			// This creates a writable mount inside the root. Also, when tmpdir points
			// to "/tmp", it makes the the actual /tmp to be mounted and not a tmpfs
			// inside the sentry.
			{
				Type:        "bind",
				Destination: TmpDir(),
				Source:      TmpDir(),
			},
		},
	}
}

// SetupRootDir creates a root directory for containers.
func SetupRootDir() (string, error) {
	rootDir, err := ioutil.TempDir(TmpDir(), "containers")
	if err != nil {
		return "", fmt.Errorf("error creating root dir: %v", err)
	}
	return rootDir, nil
}

// SetupContainer creates a bundle and root dir for the container, generates a
// test config, and writes the spec to config.json in the bundle dir.
func SetupContainer(spec *specs.Spec, conf *boot.Config) (rootDir, bundleDir string, err error) {
	rootDir, err = SetupRootDir()
	if err != nil {
		return "", "", err
	}
	conf.RootDir = rootDir
	bundleDir, err = SetupBundleDir(spec)
	return rootDir, bundleDir, err
}

// SetupBundleDir creates a bundle dir and writes the spec to config.json.
func SetupBundleDir(spec *specs.Spec) (bundleDir string, err error) {
	bundleDir, err = ioutil.TempDir(TmpDir(), "bundle")
	if err != nil {
		return "", fmt.Errorf("error creating bundle dir: %v", err)
	}

	if err = writeSpec(bundleDir, spec); err != nil {
		return "", fmt.Errorf("error writing spec: %v", err)
	}
	return bundleDir, nil
}

// writeSpec writes the spec to disk in the given directory.
func writeSpec(dir string, spec *specs.Spec) error {
	b, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(dir, "config.json"), b, 0755)
}

// UniqueContainerID generates a unique container id for each test.
//
// The container id is used to create an abstract unix domain socket, which must
// be unique.  While the container forbids creating two containers with the same
// name, sometimes between test runs the socket does not get cleaned up quickly
// enough, causing container creation to fail.
func UniqueContainerID() string {
	return fmt.Sprintf("test-container-%d", time.Now().UnixNano())
}

// Copy copies file from src to dst.
func Copy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// Poll is a shorthand function to poll for something with given timeout.
func Poll(cb func() error, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	b := backoff.WithContext(backoff.NewConstantBackOff(100*time.Millisecond), ctx)
	return backoff.Retry(cb, b)
}

// WaitForHTTP tries GET requests on a port until the call succeeds or timeout.
func WaitForHTTP(port int, timeout time.Duration) error {
	cb := func() error {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/", port))
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}
	return Poll(cb, timeout)
}

// RunAsRoot ensures the test runs with CAP_SYS_ADMIN and CAP_SYS_CHROOT. If
// needed it will create a new user namespace and re-execute the test as root
// inside of the namespace. This function returns when it's running as root. If
// it needs to create another process, it will exit from there and not return.
func RunAsRoot() {
	if specutils.HasCapabilities(capability.CAP_SYS_ADMIN, capability.CAP_SYS_CHROOT) {
		return
	}

	fmt.Println("*** Re-running test as root in new user namespace ***")

	// Current process doesn't have CAP_SYS_ADMIN, create user namespace and run
	// as root inside that namespace to get it.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command("/proc/self/exe", os.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
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
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			if ws, ok := exit.Sys().(syscall.WaitStatus); ok {
				os.Exit(ws.ExitStatus())
			}
			os.Exit(-1)
		}
		panic(fmt.Sprint("error running child process:", err.Error()))
	}
	os.Exit(0)
}

// StartReaper starts a goroutine that will reap all children processes created
// by the tests. Caller must call the returned function to stop it.
func StartReaper() func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGCHLD)
	stop := make(chan struct{})

	go func() {
		for {
			select {
			case <-ch:
			case <-stop:
				return
			}
			for {
				cpid, _ := syscall.Wait4(-1, nil, syscall.WNOHANG, nil)
				if cpid < 1 {
					break
				}
			}
		}
	}()
	return func() { stop <- struct{}{} }
}

// RetryEintr retries the function until an error different than EINTR is
// returned.
func RetryEintr(f func() (uintptr, uintptr, error)) (uintptr, uintptr, error) {
	for {
		r1, r2, err := f()
		if err != syscall.EINTR {
			return r1, r2, err
		}
	}
}

// WaitUntilRead reads from the given reader until the wanted string is found
// or until timeout.
func WaitUntilRead(r io.Reader, want string, split bufio.SplitFunc, timeout time.Duration) error {
	sc := bufio.NewScanner(r)
	if split != nil {
		sc.Split(split)
	}
	// done must be accessed atomically. A value greater than 0 indicates
	// that the read loop can exit.
	var done uint32
	doneCh := make(chan struct{})
	go func() {
		for sc.Scan() {
			t := sc.Text()
			if strings.Contains(t, want) {
				atomic.StoreUint32(&done, 1)
				close(doneCh)
				break
			}
			if atomic.LoadUint32(&done) > 0 {
				break
			}
		}
	}()
	select {
	case <-time.After(timeout):
		atomic.StoreUint32(&done, 1)
		return fmt.Errorf("timeout waiting to read %q", want)
	case <-doneCh:
		return nil
	}
}

// KillCommand kills the process running cmd unless it hasn't been started. It
// returns an error if it cannot kill the process unless the reason is that the
// process has already exited.
func KillCommand(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Kill(); err != nil {
		if !strings.Contains(err.Error(), "process already finished") {
			return fmt.Errorf("failed to kill process %v: %v", cmd, err)
		}
	}
	return nil
}

// WriteTmpFile writes text to a temporary file, closes the file, and returns
// the name of the file.
func WriteTmpFile(pattern, text string) (string, error) {
	file, err := ioutil.TempFile(TmpDir(), pattern)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := file.Write([]byte(text)); err != nil {
		return "", err
	}
	return file.Name(), nil
}
