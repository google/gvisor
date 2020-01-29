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
	"debug/elf"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/specutils"
)

var (
	checkpoint = flag.Bool("checkpoint", true, "control checkpoint/restore support")
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// IsCheckpointSupported returns the relevant command line flag.
func IsCheckpointSupported() bool {
	return *checkpoint
}

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
	var absPath string
	err := filepath.Walk(os.Getenv("TEST_SRCDIR"), func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		// Annoyingly, bazel adds the build type to the directory path for go
		// binaries, but not for c++ binaries.
		// e.g., "runsc/runsc" may be located at "test.runfiles/__main__/runsc/linux_amd64_pure_stripped/runsc".
		bazelPath := filepath.Join(filepath.Dir(filepath.Dir(p)), filepath.Base(p))
		if strings.HasSuffix(p, path) || strings.HasSuffix(bazelPath, path) {
			if absPath != "" {
				return fmt.Errorf("more than one match found for %q: %s and %s", path, absPath, p)
			}
			absPath = p
		}
		return nil
	})
	if absPath != "" {
		return absPath, nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to walk runfiles dir: %v", err)
	}
	return "", fmt.Errorf("file %q not found", path)
}

// TestConfig returns the default configuration to use in tests. Note that
// 'RootDir' must be set by caller if required.
func TestConfig() *boot.Config {
	return &boot.Config{
		Debug:           true,
		LogFormat:       "text",
		DebugLogFormat:  "text",
		AlsoLogToStderr: true,
		LogPackets:      true,
		Network:         boot.NetworkNone,
		Strace:          true,
		Platform:        "ptrace",
		FileAccess:      boot.FileAccessExclusive,
		TestOnlyAllowRunAsCurrentUserWithoutChroot: true,
		NumNetworkChannels:                         1,
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
			log.Infof("Waiting %s: %v", url, err)
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

// IsStatic returns true iff the given file is a static binary.
func IsStatic(filename string) (bool, error) {
	f, err := elf.Open(filename)
	if err != nil {
		return false, err
	}
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			return false, nil // Has interpreter.
		}
	}
	return true, nil
}

// TestBoundsForShard calculates the beginning and end indices for the test
// based on the TEST_SHARD_INDEX and TEST_TOTAL_SHARDS environment vars. The
// returned ints are the beginning (inclusive) and end (exclusive) of the
// subslice corresponding to the shard. If either of the env vars are not
// present, then the function will return bounds that include all tests. If
// there are more shards than there are tests, then the returned list may be
// empty.
func TestBoundsForShard(numTests int) (int, int, error) {
	var (
		begin = 0
		end   = numTests
	)
	indexStr, totalStr := os.Getenv("TEST_SHARD_INDEX"), os.Getenv("TEST_TOTAL_SHARDS")
	if indexStr == "" || totalStr == "" {
		return begin, end, nil
	}

	// Parse index and total to ints.
	shardIndex, err := strconv.Atoi(indexStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid TEST_SHARD_INDEX %q: %v", indexStr, err)
	}
	shardTotal, err := strconv.Atoi(totalStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid TEST_TOTAL_SHARDS %q: %v", totalStr, err)
	}

	// Calculate!
	shardSize := int(math.Ceil(float64(numTests) / float64(shardTotal)))
	begin = shardIndex * shardSize
	end = ((shardIndex + 1) * shardSize)
	if begin > numTests {
		// Nothing to run.
		return 0, 0, nil
	}
	if end > numTests {
		end = numTests
	}
	return begin, end, nil
}
