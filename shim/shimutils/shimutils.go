// Copyright 2026 The containerd Authors.
// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package shimutils provides utility functions for testing the shim. It is intended to be used in
// conjunction with the containerd testing framework.
package shimutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	task "github.com/containerd/containerd/api/runtime/task/v2"
	ttrpc "github.com/containerd/ttrpc"
	typeurl "github.com/containerd/typeurl/v2"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/shim/v1/runtimeoptions"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"

	"context"

	events "github.com/containerd/containerd/api/services/ttrpc/events/v1"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	// SocketAddress is the name of the socket file used to communicate with the shim.
	SocketAddress = "containerd.sock"
)

var (
	shimContextMutex sync.Mutex
)

// GetRunscPath returns the path to the runsc binary.
func GetRunscPath() (string, error) {
	return testutil.FindFile("runsc/runsc")
}

// GetShimPath returns the path to the containerd-shim-runsc-v1 binary.
func GetShimPath() (string, error) {
	return testutil.FindFile("shim/containerd-shim-runsc-v1")
}

// NewSandboxSpec returns a new sandbox spec.
func NewSandboxSpec() *specs.Spec {
	spec := newSpec("sleep", "100000")
	spec.Annotations[specutils.ContainerdContainerTypeAnnotation] = specutils.ContainerdContainerTypeSandbox
	return spec
}

// NewContainerSpec returns a new container spec.
func NewContainerSpec(sandboxID string, args []string) *specs.Spec {
	spec := newSpec(args...)
	spec.Annotations[specutils.ContainerdContainerTypeAnnotation] = specutils.ContainerdContainerTypeContainer
	spec.Annotations[specutils.ContainerdSandboxIDAnnotation] = sandboxID
	return spec
}

func newSpec(args ...string) *specs.Spec {
	spec := testutil.NewSpecWithArgs(args...)
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	spec.Linux.Namespaces = []specs.LinuxNamespace{
		{
			Type: specs.PIDNamespace,
		},
		{
			Type: specs.MountNamespace,
		},
		{
			Type: specs.UserNamespace,
		},
	}
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{
		{
			ContainerID: 0,
			HostID:      uint32(os.Getuid()),
			Size:        1,
		},
	}
	spec.Linux.GIDMappings = []specs.LinuxIDMapping{
		{
			ContainerID: 0,
			HostID:      uint32(os.Getgid()),
			Size:        1,
		},
	}
	spec.Process.User = specs.User{
		UID: uint32(os.Getuid()),
		GID: uint32(os.Getgid()),
	}
	return spec
}

// Container is a test container.
type Container struct {
	id     string
	bundle string
	spec   *specs.Spec
}

// NewContainer creates a new container with the given spec and returns it. It also creates the
// necessary directory structure and files for the container to run.
func NewContainer(spec *specs.Spec, containerd *MockContainerd) (*Container, error) {
	c := &Container{
		id:   testutil.RandomContainerID(),
		spec: spec,
	}

	if err := c.createDirectoryStructure(containerd.wd); err != nil {
		return nil, err
	}
	if err := c.writeSpec(spec); err != nil {
		return nil, err
	}

	return c, nil

}

// ID returns the ID of the container.
func (c *Container) ID() string {
	return c.id
}

// Bundle returns the path to the bundle directory of the container.
func (c *Container) Bundle() string {
	return c.bundle
}

func (c *Container) createDirectoryStructure(wd string) error {
	bundle := filepath.Join(wd, fmt.Sprintf("bundle-%s", c.id))
	if err := os.MkdirAll(bundle, 0o777); err != nil {
		return err
	}

	c.bundle = bundle
	return nil
}

func (c *Container) writeSpec(spec *specs.Spec) error {
	specPath := filepath.Join(c.bundle, "config.json")
	b, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	if err := os.WriteFile(specPath, b, 0755); err != nil {
		return err
	}
	return nil
}

// dummyEventsServer is a mock implementation of the events service.
type dummyEventsServer struct {
	t  *testing.T
	ch chan any

	mu     sync.Mutex
	events []any
}

// Forward forwards the event to the event channel.
func (s *dummyEventsServer) Forward(ctx context.Context, req *events.ForwardRequest) (*emptypb.Empty, error) {
	if req.Envelope != nil && req.Envelope.Event != nil {
		evt, err := typeurl.UnmarshalAny(req.Envelope.Event)
		if err != nil {
			s.t.Errorf("dummyEventsServer: failed to unmarshal event: %v", err)
			return &emptypb.Empty{}, nil
		}

		s.mu.Lock()
		s.events = append(s.events, evt)
		s.mu.Unlock()

		select {
		case s.ch <- evt:
		default:
			s.t.Logf("dummyEventsServer: event channel full, dropping from channel (still in history): %v", evt)
		}
	} else {
		s.t.Errorf("dummyEventsServer: received nil envelope or event: %+v", req)
	}
	return &emptypb.Empty{}, nil
}

func (s *dummyEventsServer) getEvents() []any {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := make([]any, len(s.events))
	copy(copied, s.events)
	return copied
}

func (s *dummyEventsServer) clearEvents() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
}

// MockContainerd plays the role of containerd to test the shim. It creates
// the necessary directory structure and files for the shim to run and sends requests to the shim.
type MockContainerd struct {
	wd            string
	shim          *exec.Cmd
	eventServer   *ttrpc.Server
	eventListener net.Listener
	EventChan     chan any
	eventWd       string
	eventSocket   string
	eventsImpl    *dummyEventsServer
}

// We need a directory structure to save and other artifacts. The directory
// structure is as follows:
//
//	working_dir/
//    config.toml // runsc config
//	  bundle-%ID%/
//	    config.json
//	  bundle-%ID2%/
//	    config.json
//	  shim.%ID%.log
//	  shim.%ID2%.log
//
// We need this directory structure to be created before we can start the
// shim.

// NewMockContainerd creates a new MockContainerd.
func NewMockContainerd(t *testing.T, shimArgs, runscArgs map[string]any) *MockContainerd {
	s := &MockContainerd{}
	// Create working directory.
	wd, err := newWorkingDir(t.Name())
	if err != nil {
		t.Fatalf("failed to create working directory: %v", err)
	}
	s.wd = wd

	if err := os.MkdirAll(s.root(), 0o777); err != nil {
		t.Fatalf("failed to create containerd root directory: %v", err)
	}

	// Set the runsc config.
	if err := newRunscConfig(s, shimArgs, runscArgs); err != nil {
		t.Fatalf("failed to create runsc config: %v", err)
	}

	// Start TTRPC event server on a short socket path under /tmp to prevent
	// "bind: invalid argument" unix socket length limit errors.
	eventWd, err := os.MkdirTemp("/tmp", "containerd-events-")
	if err != nil {
		t.Fatalf("failed to create temp dir for events: %v", err)
	}
	s.eventWd = eventWd
	s.eventSocket = filepath.Join(eventWd, "events.sock")

	if s.eventListener, err = net.Listen("unix", s.eventSocket); err != nil {
		os.RemoveAll(eventWd)
		t.Fatalf("failed to listen on events socket: %v", err)
	}

	server, err := ttrpc.NewServer()
	if err != nil {
		s.eventListener.Close()
		os.RemoveAll(eventWd)
		t.Fatalf("failed to create ttrpc server: %v", err)
	}
	s.eventServer = server

	s.EventChan = make(chan any, 128)
	s.eventsImpl = &dummyEventsServer{t: t, ch: s.EventChan}
	events.RegisterEventsService(server, s.eventsImpl)

	go func() {
		_ = server.Serve(t.Context(), s.eventListener)
	}()

	t.Cleanup(func() {
		server.Close()
		s.eventListener.Close()
		os.RemoveAll(eventWd)
	})

	return s
}

// WorkingDir returns the working directory of the mock containerd.
func (m *MockContainerd) WorkingDir() string {
	return m.wd
}

// Events returns all events received by the mock containerd.
func (m *MockContainerd) Events() []any {
	return m.eventsImpl.getEvents()
}

// ClearEvents clears the received events history.
func (m *MockContainerd) ClearEvents() {
	m.eventsImpl.clearEvents()
}

// root returns the root directory for containers.
func (m *MockContainerd) root() string {
	return filepath.Join(m.wd, "containers")
}

// StartShim starts the shim binary and waits for it to start.
func (m *MockContainerd) StartShim(t *testing.T, c *Container) error {
	f, err := os.Create(filepath.Join(m.wd, "log"))
	if err != nil {
		return fmt.Errorf("failed to create shim log file: %v", err)
	}
	defer f.Close()

	shimBinary, err := GetShimPath()
	if err != nil {
		return fmt.Errorf("failed to find shim binary: %v", err)
	}
	args := []string{
		"-namespace", "default",
		"-debug",
		"-id", c.id,
		"-socket", SocketAddress,
		"-bundle", c.bundle,
	}
	m.shim = exec.CommandContext(t.Context(), shimBinary, args...)
	m.shim.Dir = m.wd
	m.shim.Stdout = f
	m.shim.Stderr = f
	m.shim.Env = append(os.Environ(), "TTRPC_ADDRESS="+m.eventSocket)
	t.Logf("starting shim binary: %s with args: %v", shimBinary, args)
	if err := m.shim.Start(); err != nil {
		return fmt.Errorf("failed to start shim: %v", err)
	}
	t.Cleanup(func() {
		if m.shim.Process != nil {
			m.shim.Process.Kill()
		}
	})
	waitErr := make(chan error, 1)
	go func() {
		waitErr <- m.shim.Wait()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-waitErr:
			return fmt.Errorf("shim exited prematurely: %v", err)
		default:
			_, statErr := os.Stat(filepath.Join(m.wd, SocketAddress))
			if statErr == nil {
				return nil
			}
			if !os.IsNotExist(statErr) {
				return fmt.Errorf("os.Stat failed: %v", statErr)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return fmt.Errorf("shim did not start in time")
}

// GetClient returns a client to the shim socket which can be used to send requests to the shim.
func (m *MockContainerd) GetClient(t *testing.T) task.TaskService {
	var client task.TaskService
	m.withShimContext(t, func(t *testing.T) {
		conn, err := net.DialTimeout("unix", SocketAddress, 2*time.Second)
		if err != nil {
			t.Fatalf("failed to dial shim socket: %v", err)
		}
		t.Cleanup(func() {
			conn.Close()
		})
		client = task.NewTaskClient(ttrpc.NewClient(conn))
	})
	return client
}

func (m *MockContainerd) withShimContext(t *testing.T, f func(t *testing.T)) {
	shimContextMutex.Lock()
	defer shimContextMutex.Unlock()

	pwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current working directory: %v", err)
	}
	if err := os.Chdir(m.wd); err != nil {
		t.Fatalf("failed to change working directory: %v", err)
	}
	f(t)
	if err := os.Chdir(pwd); err != nil {
		t.Fatalf("failed to back to the original working directory: %v", err)
	}
}

func newRunscConfig(m *MockContainerd, shimArgs, runscArgs map[string]any) error {
	runscDebugPath := filepath.Join(m.WorkingDir(), "%ID%") + "/"
	runscPath, err := GetRunscPath()
	if err != nil {
		return fmt.Errorf("failed to find runsc binary: %v", err)
	}

	runscConfig := map[string]any{
		"debug":                   "true",
		"debug-log":               runscDebugPath,
		"TESTONLY-unsafe-nonroot": "true",
		"platform":                "systrap",
		"network":                 "none",
	}
	for k, v := range runscArgs {
		runscConfig[k] = v
	}

	config := map[string]any{
		"binary_name":  runscPath,
		"root":         m.root(),
		"runsc_config": runscConfig,
	}

	for k, v := range shimArgs {
		config[k] = v
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(config); err != nil {
		return fmt.Errorf("toml.Marshal failed: %v", err)
	}
	if err := os.WriteFile(RunscConfigPath(m.wd), buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("os.WriteFile failed: %v", err)
	}
	return nil
}

// GetRuntimeOptions returns the runtime options for the shim.
func (m *MockContainerd) GetRuntimeOptions() (*anypb.Any, error) {
	opts := &runtimeoptions.Options{
		TypeUrl:    "io.containerd.runsc.v1.options",
		ConfigPath: RunscConfigPath(m.wd),
	}
	any, err := typeurl.MarshalAny(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal runtime options: %v", err)
	}

	ret, err := typeurl.MarshalAnyToProto(any)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal runtime options to proto: %v", err)
	}
	return ret, nil
}

// RunscConfigPath returns the path to the runsc config file.
func RunscConfigPath(wd string) string {
	return filepath.Join(wd, "config.toml")
}

func newWorkingDir(name string) (string, error) {
	prefix := os.Getenv("TEST_UNDECLARED_OUTPUTS_DIR")
	if prefix == "" {
		prefix = os.Getenv("TEST_TMPDIR")
	}

	wd := filepath.Join(prefix, name)
	if err := os.MkdirAll(wd, 0o777); err != nil {
		return "", err
	}
	return wd, nil
}
