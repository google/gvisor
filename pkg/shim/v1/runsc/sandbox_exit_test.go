// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	apievents "github.com/containerd/containerd/api/events"
	task "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/stdio"
	runc "github.com/containerd/go-runc"
	"github.com/containerd/typeurl/v2"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/shim/v1/proc"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
	"gvisor.dev/gvisor/pkg/shim/v1/runtimeoptions"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
)

func init() {
	if os.Getenv("GVISOR_SANDBOX_EXIT_RUNTIME_HELPER") != "1" {
		return
	}
	if err := sandboxExitRuntimeHelper(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func sandboxExitRuntimeHelper() error {
	options := make(map[string]string)
	operation := ""
	for i, arg := range os.Args[1:] {
		switch arg {
		case "create", "start", "wait", "delete":
			operation = arg
		}
		if key, value, ok := strings.Cut(arg, "="); ok {
			options[key] = value
		} else if strings.HasPrefix(arg, "--") && i+2 < len(os.Args) {
			options[arg] = os.Args[i+2]
		}
	}
	switch operation {
	case "create":
		pid, err := runc.ReadPidFile(options["--pid-file"])
		if err != nil {
			return err
		}
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: options["--pidfd-socket"], Net: "unix"})
		if err != nil {
			return err
		}
		defer conn.Close()
		_, _, err = conn.WriteMsgUnix([]byte("pidfd"), unix.UnixRights(fd), nil)
		return err
	case "wait":
		fmt.Print(`{"exitStatus":17}`)
	case "delete":
		file, err := os.OpenFile(filepath.Join(options["--root"], "deletes"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = file.WriteString("deleted\n")
		return err
	}
	return nil
}

func sandboxExitChild(t *testing.T, bundle string) *exec.Cmd {
	t.Helper()
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	if err := os.WriteFile(filepath.Join(bundle, "init.pid"), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	return child
}

func killSandboxExitChild(t *testing.T, child *exec.Cmd) {
	t.Helper()
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
}

func newSandboxExitTest(t *testing.T) (*runscService, *Container, *exec.Cmd) {
	t.Helper()
	t.Setenv("GVISOR_SANDBOX_EXIT_RUNTIME_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	bundle := t.TempDir()
	command, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := sandboxExitChild(t, bundle)
	p := proc.New("root", &runsccmd.Runsc{Command: command, Root: bundle}, stdio.Stdio{})
	p.Bundle = bundle
	p.Sandbox = true
	p.Platform = nopPlatform{}
	if err := p.Create(t.Context(), &proc.CreateConfig{ID: p.ID(), Bundle: bundle}); err != nil {
		t.Fatal(err)
	}
	c := &Container{ID: p.ID(), task: p, sandboxExitDone: make(chan struct{})}
	s := &runscService{
		containers: map[string]*Container{c.ID: c},
		events:     make(chan any, 4),
		oomPoller:  &fakeOOMPoller{status: map[string]oomStatus{c.ID: oomNotKilled}},
	}
	t.Cleanup(func() { _ = p.Delete(context.Background()) })
	return s, c, child
}

func TestSandboxExitAfterMapRemoval(t *testing.T) {
	s, c, m := newSandboxExitTest(t)
	s.mu.Lock()
	delete(s.containers, c.ID)
	s.mu.Unlock()
	killSandboxExitChild(t, m)
	s.waitSandboxExit(c, c.task)
	c.task.Wait()
	select {
	case e := <-s.events:
		exit, ok := e.(*apievents.TaskExit)
		if !ok || exit.ContainerID != c.ID || exit.ExitStatus != proc.InternalErrorCode || exit.ExitedAt.AsTime().IsZero() {
			t.Fatalf("exit event after map removal: %+v", e)
		}
	default:
		t.Fatal("exit event lost with container map entry")
	}
}

func TestSandboxDeleteWaitsForExitAndCanRetry(t *testing.T) {
	s, c, m := newSandboxExitTest(t)
	go s.waitSandboxExit(c, c.task)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := c.Delete(ctx, &task.DeleteRequest{ID: c.ID}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("delete without host notification = %v, want deadline", err)
	}
	path := filepath.Join(c.task.Bundle, "deletes")
	if data, err := os.ReadFile(path); err != nil || string(data) != "deleted\n" {
		t.Fatalf("first runtime delete did not finish: %q, %v", data, err)
	}
	killSandboxExitChild(t, m)
	ctx, cancelRetry := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelRetry()
	response, err := s.Delete(ctx, &task.DeleteRequest{ID: c.ID})
	if err != nil {
		t.Fatalf("delete retry: %v", err)
	}
	if response.ExitStatus != proc.InternalErrorCode || response.ExitedAt.AsTime().IsZero() {
		t.Fatalf("Delete returned incomplete exit metadata: %+v", response)
	}
	if len(s.events) != 1 {
		t.Fatalf("Delete returned before exactly one exit was queued: %d events", len(s.events))
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "deleted\n" {
		t.Fatalf("retry repeated runtime deletion: %q, %v", data, err)
	}
	s.mu.Lock()
	_, retained := s.containers[c.ID]
	s.mu.Unlock()
	if retained {
		t.Fatal("completed delete retained the container")
	}
}

func TestSandboxDeleteAfterSuccessfulStart(t *testing.T) {
	s, c, _ := newSandboxExitTest(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go s.waitSandboxExit(c, c.task)
	if _, err := s.Start(ctx, &task.StartRequest{ID: c.ID}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// The host remains alive, so only the successful Start can end this wait.
	select {
	case <-c.sandboxExitDone:
	case <-ctx.Done():
		t.Fatal("successful Start did not finish the pre-start exit watcher")
	}
	if len(s.events) != 1 {
		t.Fatalf("Start queued %d events, want only TaskStart", len(s.events))
	}
	if e, ok := (<-s.events).(*apievents.TaskStart); !ok || e.ContainerID != c.ID || e.Pid != uint32(c.task.Pid()) {
		t.Fatalf("first event = %+v, want TaskStart", e)
	}
	select {
	case e := <-proc.ExitCh:
		if e.ID != c.ID || e.Status != 17 {
			t.Fatalf("normal waiter exit = %+v, want guest status 17", e)
		}
		s.checkProcesses(ctx, e)
	case <-ctx.Done():
		t.Fatal("normal waiter did not complete")
	}
	response, err := s.Delete(ctx, &task.DeleteRequest{ID: c.ID})
	if err != nil {
		t.Fatalf("Delete after normal exit: %v", err)
	}
	if response.ExitStatus != 17 || response.ExitedAt.AsTime().IsZero() || response.Pid != uint32(c.task.Pid()) {
		t.Fatalf("Delete did not retain guest exit metadata: %+v", response)
	}
	if len(s.events) != 1 {
		t.Fatalf("normal exit and Delete queued %d events, want one TaskExit", len(s.events))
	}
	if e, ok := (<-s.events).(*apievents.TaskExit); !ok || e.ContainerID != c.ID || e.ID != c.ID || e.ExitStatus != 17 || e.Pid != response.Pid || !e.ExitedAt.AsTime().Equal(response.ExitedAt.AsTime()) {
		t.Fatalf("exit event = %+v, want guest exit matching Delete", e)
	}
	s.mu.Lock()
	_, retained := s.containers[c.ID]
	s.mu.Unlock()
	if retained {
		t.Fatal("completed delete retained the container")
	}
}

type countingOOMPoller struct {
	fakeOOMPoller
	calls int
}

func (p *countingOOMPoller) isOOM(id string) oomStatus {
	p.calls++
	return p.fakeOOMPoller.isOOM(id)
}

func TestSandboxBufferedExitDoesNotConsumeStartedOOM(t *testing.T) {
	s, c, m := newSandboxExitTest(t)
	poller := &countingOOMPoller{fakeOOMPoller: fakeOOMPoller{status: map[string]oomStatus{c.ID: oomKilledUnpublished}}}
	s.oomPoller = poller
	killSandboxExitChild(t, m)
	if err := c.task.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	s.waitSandboxExit(c, c.task)
	if poller.calls != 0 || len(s.events) != 0 {
		t.Fatal("pre-start watcher stole OOM or published a duplicate exit")
	}
	select {
	case e := <-proc.ExitCh:
		if e.Status != 17 {
			t.Fatalf("guest status = %d, want 17", e.Status)
		}
		s.checkProcesses(t.Context(), e)
	case <-time.After(5 * time.Second):
		t.Fatal("normal waiter did not complete")
	}
	if poller.calls != 1 || len(s.events) != 2 {
		t.Fatal("normal waiter lost OOM ownership")
	}
	if _, ok := (<-s.events).(*apievents.TaskOOM); !ok {
		t.Fatal("TaskOOM did not precede TaskExit")
	}
	if e := (<-s.events).(*apievents.TaskExit); e.ExitStatus != 17 {
		t.Fatalf("normal guest exit status changed: %+v", e)
	}
}

func TestSandboxPreStartOOM(t *testing.T) {
	s, c, m := newSandboxExitTest(t)
	s.oomPoller = &fakeOOMPoller{status: map[string]oomStatus{c.ID: oomKilledUnpublished}}
	killSandboxExitChild(t, m)
	s.waitSandboxExit(c, c.task)
	if c.task.ExitStatus() != 137 || len(s.events) != 2 {
		t.Fatal("pre-start OOM did not correct status and publish both events")
	}
	if _, ok := (<-s.events).(*apievents.TaskOOM); !ok {
		t.Fatal("TaskOOM did not precede TaskExit")
	}
	if e := (<-s.events).(*apievents.TaskExit); e.ExitStatus != 137 {
		t.Fatalf("pre-start OOM status = %d", e.ExitStatus)
	}
}

type failedOOMPoller struct{ fakeOOMPoller }

func (*failedOOMPoller) add(string, any) error { return errors.New("OOM setup failed") }

func TestSandboxExitAfterCreateOOMSetupFailure(t *testing.T) {
	t.Setenv("GVISOR_SANDBOX_EXIT_RUNTIME_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	bundle := t.TempDir()
	child := sandboxExitChild(t, bundle)
	if err := utils.WriteSpec(bundle, &specs.Spec{}); err != nil {
		t.Fatal(err)
	}
	command, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(bundle, "runtime.toml")
	if err := os.WriteFile(config, []byte(fmt.Sprintf("binary_name = %q\nroot = %q\n", command, bundle)), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, err := typeurl.MarshalAnyToProto(&runtimeoptions.Options{ConfigPath: config})
	if err != nil {
		t.Fatal(err)
	}
	s := &runscService{platform: nopPlatform{}, containers: make(map[string]*Container), events: make(chan any, 4),
		oomPoller: &failedOOMPoller{fakeOOMPoller{status: make(map[string]oomStatus)}}}
	ctx := namespaces.WithNamespace(t.Context(), "test")
	if _, err := s.Create(ctx, &task.CreateTaskRequest{ID: "root", Bundle: bundle, Options: opts}); err == nil {
		t.Fatal("Create did not report OOM setup failure")
	}
	c, err := s.getContainer("root")
	if err != nil {
		t.Fatalf("Create failed before registering its task: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(c.task.Rootfs)
		_ = c.task.Delete(context.Background())
	})
	killSandboxExitChild(t, child)
	select {
	case <-c.sandboxExitDone:
		if c.task.ExitStatus() != proc.InternalErrorCode || len(s.events) != 1 {
			t.Fatal("Create error lost host death notification")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Create error did not activate its exit watcher")
	}
}
