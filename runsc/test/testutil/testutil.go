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

// Package testutil contains utility functions for runsc tests.
package testutil

import (
	"bufio"
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

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

	// Annoyingly, bazel adds the build type to the directory path for go
	// binaries, but not for c++ binaries. We use two different patterns to
	// to find our file.
	patterns := []string{
		// Try the obvious path first.
		filepath.Join(root, path),
		// If it was a go binary, use a wildcard to match the build
		// type. The pattern is: /test-path/__main__/directories/*/file.
		filepath.Join(root, filepath.Dir(path), "*", filepath.Base(path)),
	}

	for _, p := range patterns {
		matches, err := filepath.Glob(p)
		if err != nil {
			// "The only possible returned error is ErrBadPattern,
			// when pattern is malformed." -godoc
			return "", fmt.Errorf("error globbing %q: %v", p, err)
		}
		switch len(matches) {
		case 0:
			// Try the next pattern.
		case 1:
			// We found it.
			return matches[0], nil
		default:
			return "", fmt.Errorf("more than one match found for %q: %s", path, matches)
		}
	}
	return "", fmt.Errorf("file %q not found", path)
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
		NumNetworkChannels:                         1,
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
			Capabilities: specutils.AllCapabilities(),
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
		Hostname: "runsc-test-hostname",
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
	// Read 20 random bytes.
	b := make([]byte, 20)
	// "[Read] always returns len(p) and a nil error." --godoc
	if _, err := rand.Read(b); err != nil {
		panic("rand.Read failed: " + err.Error())
	}
	// base32 encode the random bytes, so that the name is a valid
	// container id and can be used as a socket name in the filesystem.
	return fmt.Sprintf("test-container-%s", base32.StdEncoding.EncodeToString(b))
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
		c := &http.Client{
			// Calculate timeout to be able to do minimum 5 attempts.
			Timeout: timeout / 5,
		}
		url := fmt.Sprintf("http://localhost:%d/", port)
		resp, err := c.Get(url)
		if err != nil {
			log.Printf("Waiting %s: %v", url, err)
			return err
		}
		resp.Body.Close()
		return nil
	}
	return Poll(cb, timeout)
}

// Reaper reaps child processes.
type Reaper struct {
	// mu protects ch, which will be nil if the reaper is not running.
	mu sync.Mutex
	ch chan os.Signal
}

// Start starts reaping child processes.
func (r *Reaper) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ch != nil {
		panic("reaper.Start called on a running reaper")
	}

	r.ch = make(chan os.Signal, 1)
	signal.Notify(r.ch, syscall.SIGCHLD)

	go func() {
		for {
			r.mu.Lock()
			ch := r.ch
			r.mu.Unlock()
			if ch == nil {
				return
			}

			_, ok := <-ch
			if !ok {
				// Channel closed.
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
}

// Stop stops reaping child processes.
func (r *Reaper) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ch == nil {
		panic("reaper.Stop called on a stopped reaper")
	}

	signal.Stop(r.ch)
	close(r.ch)
	r.ch = nil
}

// StartReaper is a helper that starts a new Reaper and returns a function to
// stop it.
func StartReaper() func() {
	r := &Reaper{}
	r.Start()
	return r.Stop
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

// RandomName create a name with a 6 digit random number appended to it.
func RandomName(prefix string) string {
	return fmt.Sprintf("%s-%06d", prefix, rand.Int31n(1000000))
}
