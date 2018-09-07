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

// Package testutil contains utility functions for runsc tests.
package testutil

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
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
	// it backwards from the in the working directory.
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

// TestConfig return the default configuration to use in tests.
func TestConfig() *boot.Config {
	return &boot.Config{
		Debug:          true,
		LogFormat:      "text",
		LogPackets:     true,
		Network:        boot.NetworkNone,
		Strace:         true,
		MultiContainer: true,
		FileAccess:     boot.FileAccessProxyExclusive,
		TestOnlyAllowRunAsCurrentUserWithoutChroot: true,
	}
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
			specs.Mount{
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
	bundleDir, err = SetupContainerInRoot(rootDir, spec, conf)
	return rootDir, bundleDir, err
}

// SetupContainerInRoot creates a bundle for the container, generates a test
// config, and writes the spec to config.json in the bundle dir.
func SetupContainerInRoot(rootDir string, spec *specs.Spec, conf *boot.Config) (bundleDir string, err error) {
	bundleDir, err = ioutil.TempDir(TmpDir(), "bundle")
	if err != nil {
		return "", fmt.Errorf("error creating bundle dir: %v", err)
	}

	if err = writeSpec(bundleDir, spec); err != nil {
		return "", fmt.Errorf("error writing spec: %v", err)
	}

	conf.RootDir = rootDir
	conf.SpecFile = filepath.Join(bundleDir, "config.json")
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
		_, err := http.Get(fmt.Sprintf("http://localhost:%d/", port))
		return err
	}
	return Poll(cb, timeout)
}

// RunAsRoot ensures the test runs with CAP_SYS_ADMIN. If need it will create
// a new user namespace and reexecute the test as root inside of the namespace.
func RunAsRoot(m *testing.M) {
	if specutils.HasCapSysAdmin() {
		// Capability: check! Good to run.
		os.Exit(m.Run())
	}

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
