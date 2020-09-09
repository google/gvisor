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

package boot

import (
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/control/server"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/fsgofer"
)

func init() {
	log.SetLevel(log.Debug)
	rand.Seed(time.Now().UnixNano())
	if err := fsgofer.OpenProcSelfFD(); err != nil {
		panic(err)
	}
	config.RegisterFlags()
}

func testConfig() *config.Config {
	conf, err := config.NewFromFlags()
	if err != nil {
		panic(err)
	}
	// Change test defaults.
	conf.RootDir = "unused_root_dir"
	conf.Network = config.NetworkNone
	conf.DisableSeccomp = true
	return conf
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
	at, err := fsgofer.NewAttachPoint(root, fsgofer.Config{ROMount: true})
	if err != nil {
		return 0, nil, err
	}
	go func() {
		s := p9.NewServer(at)
		if err := s.Handle(socket); err != nil {
			log.Infof("Gofer is stopping. FD: %d, err: %v\n", goferEnd, err)
		}
	}()
	// Closing the gofer socket will stop the gofer and exit goroutine above.
	cleanup := func() {
		if err := socket.Close(); err != nil {
			log.Warningf("Error closing gofer socket: %v", err)
		}
	}
	return sandboxEnd, cleanup, nil
}

func createLoader(vfsEnabled bool, spec *specs.Spec) (*Loader, func(), error) {
	fd, err := server.CreateSocket(ControlSocketAddr(fmt.Sprintf("%010d", rand.Int())[:10]))
	if err != nil {
		return nil, nil, err
	}
	conf := testConfig()
	conf.VFS2 = vfsEnabled

	sandEnd, cleanup, err := startGofer(spec.Root.Path)
	if err != nil {
		return nil, nil, err
	}

	// Loader takes ownership of stdio.
	var stdio []int
	for _, f := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		newFd, err := unix.Dup(int(f.Fd()))
		if err != nil {
			return nil, nil, err
		}
		stdio = append(stdio, newFd)
	}

	args := Args{
		ID:           "foo",
		Spec:         spec,
		Conf:         conf,
		ControllerFD: fd,
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
	doRun(t, false)
}

// TestRunVFS2 runs TestRun in VFSv2.
func TestRunVFS2(t *testing.T) {
	doRun(t, true)
}

func doRun(t *testing.T, vfsEnabled bool) {
	l, cleanup, err := createLoader(vfsEnabled, testSpec())
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
	doStartSignal(t, false)
}

// TestStartSignalVFS2 does TestStartSignal with VFS2.
func TestStartSignalVFS2(t *testing.T) {
	doStartSignal(t, true)
}

func doStartSignal(t *testing.T, vfsEnabled bool) {
	l, cleanup, err := createLoader(vfsEnabled, testSpec())
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

type CreateMountTestcase struct {
	name string
	// Spec that will be used to create the mount manager.  Note
	// that we can't mount procfs without a kernel, so each spec
	// MUST contain something other than procfs mounted at /proc.
	spec specs.Spec
	// Paths that are expected to exist in the resulting fs.
	expectedPaths []string
}

func createMountTestcases(vfs2 bool) []*CreateMountTestcase {
	testCases := []*CreateMountTestcase{
		&CreateMountTestcase{
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
		&CreateMountTestcase{
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
		&CreateMountTestcase{
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
	}

	vfsCase := &CreateMountTestcase{
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
				// TODO (gvisor.dev/issue/1487): Re-add this case when sysfs supports
				//  MkDirAt in VFS2 (and remove the reduntant append).
				// {
				//		Destination: "/sys/bar",
				//		Type:        "tmpfs",
				//	},
				//
				{
					Destination: "/tmp/baz",
					Type:        "tmpfs",
				},
			},
		},
		expectedPaths: []string{"/proc", "/sys" /* "/sys/bar" ,*/, "/tmp", "/tmp/baz"},
	}

	if !vfs2 {
		vfsCase.spec.Mounts = append(vfsCase.spec.Mounts, specs.Mount{Destination: "/sys/bar", Type: "tmpfs"})
		vfsCase.expectedPaths = append(vfsCase.expectedPaths, "/sys/bar")
	}
	return append(testCases, vfsCase)
}

// Test that MountNamespace can be created with various specs.
func TestCreateMountNamespace(t *testing.T) {
	for _, tc := range createMountTestcases(false /* vfs2 */) {
		t.Run(tc.name, func(t *testing.T) {
			conf := testConfig()
			ctx := contexttest.Context(t)

			sandEnd, cleanup, err := startGofer(tc.spec.Root.Path)
			if err != nil {
				t.Fatalf("failed to create gofer: %v", err)
			}
			defer cleanup()

			mntr := newContainerMounter(&tc.spec, []*fd.FD{fd.New(sandEnd)}, nil, &podMountHints{})
			mns, err := mntr.createMountNamespace(ctx, conf)
			if err != nil {
				t.Fatalf("failed to create mount namespace: %v", err)
			}
			ctx = fs.WithRoot(ctx, mns.Root())
			if err := mntr.mountSubmounts(ctx, conf, mns); err != nil {
				t.Fatalf("failed to create mount namespace: %v", err)
			}

			root := mns.Root()
			defer root.DecRef(ctx)
			for _, p := range tc.expectedPaths {
				maxTraversals := uint(0)
				if d, err := mns.FindInode(ctx, root, root, p, &maxTraversals); err != nil {
					t.Errorf("expected path %v to exist with spec %v, but got error %v", p, tc.spec, err)
				} else {
					d.DecRef(ctx)
				}
			}
		})
	}
}

// Test that MountNamespace can be created with various specs.
func TestCreateMountNamespaceVFS2(t *testing.T) {
	for _, tc := range createMountTestcases(true /* vfs2 */) {
		t.Run(tc.name, func(t *testing.T) {
			spec := testSpec()
			spec.Mounts = tc.spec.Mounts
			spec.Root = tc.spec.Root

			t.Logf("Using root: %q", spec.Root.Path)
			l, loaderCleanup, err := createLoader(true /* VFS2 Enabled */, spec)
			if err != nil {
				t.Fatalf("failed to create loader: %v", err)
			}
			defer l.Destroy()
			defer loaderCleanup()

			mntr := newContainerMounter(l.root.spec, l.root.goferFDs, l.k, l.mountHints)
			if err := mntr.processHints(l.root.conf, l.root.procArgs.Credentials); err != nil {
				t.Fatalf("failed process hints: %v", err)
			}

			ctx := l.k.SupervisorContext()
			mns, err := mntr.mountAll(l.root.conf, &l.root.procArgs)
			if err != nil {
				t.Fatalf("mountAll: %v", err)
			}

			root := mns.Root()
			defer root.DecRef(ctx)
			for _, p := range tc.expectedPaths {
				target := &vfs.PathOperation{
					Root:  root,
					Start: root,
					Path:  fspath.Parse(p),
				}

				if d, err := l.k.VFS().GetDentryAt(ctx, l.root.procArgs.Credentials, target, &vfs.GetDentryOptions{}); err != nil {
					t.Errorf("expected path %v to exist with spec %v, but got error %v", p, tc.spec, err)
				} else {
					d.DecRef(ctx)
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
							Dev:        "9pfs-/",
							Flags:      fs.MountSourceFlags{ReadOnly: true},
							DataString: "trans=fd,rfdno=0,wfdno=0,privateunixsocket=true",
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
							Dev:        "9pfs-/",
							Flags:      fs.MountSourceFlags{ReadOnly: true},
							DataString: "trans=fd,rfdno=0,wfdno=0,privateunixsocket=true",
						},
						{
							Dev:        "9pfs-/dev/fd-foo",
							DataString: "trans=fd,rfdno=1,wfdno=1,privateunixsocket=true,cache=remote_revalidating",
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
							Dev:        "9pfs-/",
							Flags:      fs.MountSourceFlags{ReadOnly: true},
							DataString: "trans=fd,rfdno=0,wfdno=0,privateunixsocket=true",
						},
					},
					"tmpfs": {
						{
							Dev:        "none",
							Flags:      fs.MountSourceFlags{NoAtime: true},
							DataString: "uid=1022",
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
			var ioFDs []*fd.FD
			for _, ioFD := range tc.ioFDs {
				ioFDs = append(ioFDs, fd.New(ioFD))
			}
			mntr := newContainerMounter(tc.spec, ioFDs, nil, &podMountHints{})
			actualRenv, err := mntr.createRestoreEnvironment(conf)
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
