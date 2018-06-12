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
	"io/ioutil"
	"os"
	"sync"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/control/server"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
)

func init() {
	log.SetLevel(log.Debug)
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

func createLoader() (*Loader, error) {
	fd, err := server.CreateSocket(ControlSocketAddr("123"))
	if err != nil {
		return nil, err
	}
	conf := &Config{
		RootDir:        "unused_root_dir",
		Network:        NetworkNone,
		FileAccess:     FileAccessDirect,
		DisableSeccomp: true,
	}
	return New(testSpec(), conf, fd, nil, false)
}

// TestRun runs a simple application in a sandbox and checks that it succeeds.
func TestRun(t *testing.T) {
	s, err := createLoader()
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer s.Destroy()

	// Start a goroutine to read the start chan result, otherwise Run will
	// block forever.
	var resultChanErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		resultChanErr = <-s.ctrl.manager.startResultChan
		wg.Done()
	}()

	// Run the container..
	if err := s.Run(); err != nil {
		t.Errorf("error running container: %v", err)
	}

	// We should have not gotten an error on the startResultChan.
	wg.Wait()
	if resultChanErr != nil {
		t.Errorf("error on startResultChan: %v", resultChanErr)
	}

	// Wait for the application to exit.  It should succeed.
	if status := s.WaitExit(); status.Code != 0 || status.Signo != 0 {
		t.Errorf("application exited with status %+v, want 0", status)
	}
}

// TestStartSignal tests that the controller Start message will cause
// WaitForStartSignal to return.
func TestStartSignal(t *testing.T) {
	s, err := createLoader()
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer s.Destroy()

	// We aren't going to wait on this application, so the control server
	// needs to be shut down manually.
	defer s.ctrl.srv.Stop()

	// Start a goroutine that calls WaitForStartSignal and writes to a
	// channel when it returns.
	waitFinished := make(chan struct{})
	go func() {
		s.WaitForStartSignal()
		// Pretend that Run() executed and returned no error.
		s.ctrl.manager.startResultChan <- nil
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
	if err := s.ctrl.manager.StartRoot(nil, nil); err != nil {
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
	conf := &Config{
		RootDir:        "unused_root_dir",
		FileAccess:     FileAccessDirect,
		DisableSeccomp: true,
	}

	testFile, err := ioutil.TempFile(os.TempDir(), "create-mount-namespace-")
	if err != nil {
		t.Fatalf("ioutil.TempFile() failed, err: %v", err)
	}
	defer os.RemoveAll(testFile.Name())

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
						Source:      testFile.Name(),
						Type:        "bind",
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
	}

	for _, tc := range testCases {
		ctx := contexttest.Context(t)
		mm, err := createMountNamespace(ctx, ctx, &tc.spec, conf, nil)
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
	}
}
