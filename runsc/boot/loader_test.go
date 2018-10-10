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

package boot

import (
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/control/server"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/unet"
	"gvisor.googlesource.com/gvisor/runsc/fsgofer"
)

func init() {
	log.SetLevel(log.Debug)
	rand.Seed(time.Now().UnixNano())
}

func testConfig() *Config {
	return &Config{
		RootDir:        "unused_root_dir",
		Network:        NetworkNone,
		DisableSeccomp: true,
	}
}

// testSpec returns a simple spec that can be used in tests.
func testSpec() *specs.Spec {
	return &specs.Spec{
		// The host filesystem root is the sandbox root.
		Root: &specs.Root{
			Path:     "/",
			Readonly: true,
		},
		Process: &specs.Process{
			Args: []string{"/bin/true"},
		},
	}
}

// startGofer starts a new gofer routine serving 'root' path. It returns the
// sandbox side of the connection, and a function that when called will stop the
// gofer.
func startGofer(root string) (int, func(), error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, nil, err
	}
	sandboxEnd, goferEnd := fds[0], fds[1]

	socket, err := unet.NewSocket(goferEnd)
	if err != nil {
		syscall.Close(sandboxEnd)
		syscall.Close(goferEnd)
		return 0, nil, fmt.Errorf("error creating server on FD %d: %v", goferEnd, err)
	}
	go func() {
		at := fsgofer.NewAttachPoint(root, fsgofer.Config{ROMount: true})
		s := p9.NewServer(at)
		if err := s.Handle(socket); err != nil {
			log.Infof("Gofer is stopping. FD: %d, err: %v\n", goferEnd, err)
		}
	}()
	// Closing the gofer FD will stop the gofer and exit goroutine above.
	return sandboxEnd, func() { syscall.Close(goferEnd) }, nil
}

func createLoader() (*Loader, func(), error) {
	fd, err := server.CreateSocket(ControlSocketAddr(fmt.Sprintf("%010d", rand.Int())[:10]))
	if err != nil {
		return nil, nil, err
	}
	conf := testConfig()
	spec := testSpec()

	sandEnd, cleanup, err := startGofer(spec.Root.Path)
	if err != nil {
		return nil, nil, err
	}

	stdio := []int{int(os.Stdin.Fd()), int(os.Stdout.Fd()), int(os.Stderr.Fd())}
	args := Args{
		ID:           "foo",
		Spec:         spec,
		Conf:         conf,
		ControllerFD: fd,
		DeviceFD:     -1,
		GoferFDs:     []int{sandEnd},
		StdioFDs:     stdio,
	}
	l, err := New(args)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return l, cleanup, nil
}

// TestRun runs a simple application in a sandbox and checks that it succeeds.
func TestRun(t *testing.T) {
	l, cleanup, err := createLoader()
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer l.Destroy()
	defer cleanup()

	// Start a goroutine to read the start chan result, otherwise Run will
	// block forever.
	var resultChanErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		resultChanErr = <-l.ctrl.manager.startResultChan
		wg.Done()
	}()

	// Run the container.
	if err := l.Run(); err != nil {
		t.Errorf("error running container: %v", err)
	}

	// We should have not gotten an error on the startResultChan.
	wg.Wait()
	if resultChanErr != nil {
		t.Errorf("error on startResultChan: %v", resultChanErr)
	}

	// Wait for the application to exit.  It should succeed.
	if status := l.WaitExit(); status.Code != 0 || status.Signo != 0 {
		t.Errorf("application exited with status %+v, want 0", status)
	}
}

// TestStartSignal tests that the controller Start message will cause
// WaitForStartSignal to return.
func TestStartSignal(t *testing.T) {
	l, cleanup, err := createLoader()
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer l.Destroy()
	defer cleanup()

	// We aren't going to wait on this application, so the control server
	// needs to be shut down manually.
	defer l.ctrl.srv.Stop()

	// Start a goroutine that calls WaitForStartSignal and writes to a
	// channel when it returns.
	waitFinished := make(chan struct{})
	go func() {
		l.WaitForStartSignal()
		// Pretend that Run() executed and returned no error.
		l.ctrl.manager.startResultChan <- nil
		waitFinished <- struct{}{}
	}()

	// Nothing has been written to the channel, so waitFinished should not
	// return.  Give it a little bit of time to make sure the goroutine has
	// started.
	select {
	case <-waitFinished:
		t.Errorf("WaitForStartSignal completed but it should not have")
	case <-time.After(50 * time.Millisecond):
		// OK.
	}

	// Trigger the control server StartRoot method.
	cid := "foo"
	if err := l.ctrl.manager.StartRoot(&cid, nil); err != nil {
		t.Errorf("error calling StartRoot: %v", err)
	}

	// Now WaitForStartSignal should return (within a short amount of
	// time).
	select {
	case <-waitFinished:
		// OK.
	case <-time.After(50 * time.Millisecond):
		t.Errorf("WaitForStartSignal did not complete but it should have")
	}

}

// Test that MountNamespace can be created with various specs.
func TestCreateMountNamespace(t *testing.T) {
	testCases := []struct {
		name string
		// Spec that will be used to create the mount manager.  Note
		// that we can't mount procfs without a kernel, so each spec
		// MUST contain something other than procfs mounted at /proc.
		spec specs.Spec
		// Paths that are expected to exist in the resulting fs.
		expectedPaths []string
	}{
		{
			// Only proc.
			name: "only proc mount",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
				},
			},
			// /proc, /dev, and /sys should always be mounted.
			expectedPaths: []string{"/proc", "/dev", "/sys"},
		},
		{
			// Mount at a deep path, with many components that do
			// not exist in the root.
			name: "deep mount path",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/some/very/very/deep/path",
						Type:        "tmpfs",
					},
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
				},
			},
			// /some/deep/path should be mounted, along with /proc,
			// /dev, and /sys.
			expectedPaths: []string{"/some/very/very/deep/path", "/proc", "/dev", "/sys"},
		},
		{
			// Mounts are nested inside each other.
			name: "nested mounts",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
					{
						Destination: "/foo",
						Type:        "tmpfs",
					},
					{
						Destination: "/foo/qux",
						Type:        "tmpfs",
					},
					{
						// File mounts with the same prefix.
						Destination: "/foo/qux-quz",
						Type:        "tmpfs",
					},
					{
						Destination: "/foo/bar",
						Type:        "tmpfs",
					},
					{
						Destination: "/foo/bar/baz",
						Type:        "tmpfs",
					},
					{
						// A deep path that is in foo but not the other mounts.
						Destination: "/foo/some/very/very/deep/path",
						Type:        "tmpfs",
					},
				},
			},
			expectedPaths: []string{"/foo", "/foo/bar", "/foo/bar/baz", "/foo/qux",
				"/foo/qux-quz", "/foo/some/very/very/deep/path", "/proc", "/dev", "/sys"},
		},
		{
			name: "mount inside /dev",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
					{
						Destination: "/dev",
						Type:        "tmpfs",
					},
					{
						// Mounted by runsc by default.
						Destination: "/dev/fd",
						Type:        "tmpfs",
					},
					{
						// Mount with the same prefix.
						Destination: "/dev/fd-foo",
						Type:        "tmpfs",
					},
					{
						// Unsupported fs type.
						Destination: "/dev/mqueue",
						Type:        "mqueue",
					},
					{
						Destination: "/dev/foo",
						Type:        "tmpfs",
					},
					{
						Destination: "/dev/bar",
						Type:        "tmpfs",
					},
				},
			},
			expectedPaths: []string{"/proc", "/dev", "/dev/fd-foo", "/dev/foo", "/dev/bar", "/sys"},
		},
		{
			name: "mounts inside mandatory mounts",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
					// We don't include /sys, and /tmp in
					// the spec, since they will be added
					// automatically.
					//
					// Instead, add submounts inside these
					// directories and make sure they are
					// visible under the mandatory mounts.
					{
						Destination: "/sys/bar",
						Type:        "tmpfs",
					},
					{
						Destination: "/tmp/baz",
						Type:        "tmpfs",
					},
				},
			},
			expectedPaths: []string{"/proc", "/sys", "/sys/bar", "/tmp", "/tmp/baz"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := testConfig()
			ctx := contexttest.Context(t)

			sandEnd, cleanup, err := startGofer(tc.spec.Root.Path)
			if err != nil {
				t.Fatalf("failed to create gofer: %v", err)
			}
			defer cleanup()

			mm, err := createMountNamespace(ctx, ctx, &tc.spec, conf, []int{sandEnd})
			if err != nil {
				t.Fatalf("createMountNamespace test case %q failed: %v", tc.name, err)
			}
			defer mm.DecRef()
			root := mm.Root()
			defer root.DecRef()
			for _, p := range tc.expectedPaths {
				if _, err := mm.FindInode(ctx, root, root, p, 0); err != nil {
					t.Errorf("expected path %v to exist with spec %v, but got error %v", p, tc.spec, err)
				}
			}
		})
	}
}

// TestRestoreEnvironment tests that the correct mounts are collected from the spec and config
// in order to build the environment for restoring.
func TestRestoreEnvironment(t *testing.T) {
	testCases := []struct {
		name          string
		spec          *specs.Spec
		ioFDs         []int
		errorExpected bool
		expectedRenv  fs.RestoreEnvironment
	}{
		{
			name: "basic spec test",
			spec: &specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/some/very/very/deep/path",
						Type:        "tmpfs",
					},
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
				},
			},
			ioFDs:         []int{0},
			errorExpected: false,
			expectedRenv: fs.RestoreEnvironment{
				MountSources: map[string][]fs.MountArgs{
					"9p": {
						{
							Dev:   "9pfs-/",
							Flags: fs.MountSourceFlags{ReadOnly: true},
							Data:  "trans=fd,rfdno=0,wfdno=0,privateunixsocket=true,cache=remote_revalidating",
						},
					},
					"tmpfs": {
						{
							Dev: "none",
						},
						{
							Dev: "none",
						},
						{
							Dev: "none",
						},
					},
					"devtmpfs": {
						{
							Dev: "none",
						},
					},
					"devpts": {
						{
							Dev: "none",
						},
					},
					"sysfs": {
						{
							Dev: "none",
						},
					},
				},
			},
		},
		{
			name: "bind type test",
			spec: &specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/dev/fd-foo",
						Type:        "bind",
					},
				},
			},
			ioFDs:         []int{0, 1},
			errorExpected: false,
			expectedRenv: fs.RestoreEnvironment{
				MountSources: map[string][]fs.MountArgs{
					"9p": {
						{
							Dev:   "9pfs-/",
							Flags: fs.MountSourceFlags{ReadOnly: true},
							Data:  "trans=fd,rfdno=0,wfdno=0,privateunixsocket=true,cache=remote_revalidating",
						},
						{
							Dev:  "9pfs-/dev/fd-foo",
							Data: "trans=fd,rfdno=1,wfdno=1,privateunixsocket=true,cache=remote_revalidating",
						},
					},
					"tmpfs": {
						{
							Dev: "none",
						},
					},
					"devtmpfs": {
						{
							Dev: "none",
						},
					},
					"devpts": {
						{
							Dev: "none",
						},
					},
					"proc": {
						{
							Dev: "none",
						},
					},
					"sysfs": {
						{
							Dev: "none",
						},
					},
				},
			},
		},
		{
			name: "options test",
			spec: &specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/dev/fd-foo",
						Type:        "tmpfs",
						Options:     []string{"uid=1022", "noatime"},
					},
				},
			},
			ioFDs:         []int{0},
			errorExpected: false,
			expectedRenv: fs.RestoreEnvironment{
				MountSources: map[string][]fs.MountArgs{
					"9p": {
						{
							Dev:   "9pfs-/",
							Flags: fs.MountSourceFlags{ReadOnly: true},
							Data:  "trans=fd,rfdno=0,wfdno=0,privateunixsocket=true,cache=remote_revalidating",
						},
					},
					"tmpfs": {
						{
							Dev: "none",
						},
						{
							Dev:   "none",
							Flags: fs.MountSourceFlags{NoAtime: true},
							Data:  "uid=1022",
						},
					},
					"devtmpfs": {
						{
							Dev: "none",
						},
					},
					"devpts": {
						{
							Dev: "none",
						},
					},
					"proc": {
						{
							Dev: "none",
						},
					},
					"sysfs": {
						{
							Dev: "none",
						},
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := testConfig()
			fds := &fdDispenser{fds: tc.ioFDs}
			actualRenv, err := createRestoreEnvironment(tc.spec, conf, fds)
			if !tc.errorExpected && err != nil {
				t.Fatalf("could not create restore environment for test:%s", tc.name)
			} else if tc.errorExpected {
				if err == nil {
					t.Errorf("expected an error, but no error occurred.")
				}
			} else {
				if !reflect.DeepEqual(*actualRenv, tc.expectedRenv) {
					t.Errorf("restore environments did not match for test:%s\ngot:%+v\nwant:%+v\n", tc.name, *actualRenv, tc.expectedRenv)
				}
			}
		})
	}
}
