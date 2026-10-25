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

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/control/server"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestNotFound(t *testing.T) {
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Parse([]string{"123"})
	dir, err := os.MkdirTemp("", "metadata")
	if err != nil {
		t.Fatalf("error creating dir: %v", err)
	}
	conf := &config.Config{RootDir: dir}

	d := Delete{}
	if err := d.execute(f, conf); err == nil {
		t.Error("Deleting non-existent container should have failed")
	}

	d = Delete{force: true}
	if err := d.execute(f, conf); err != nil {
		t.Errorf("Deleting non-existent container with --force should NOT have failed: %v", err)
	}
}

// writeStateFile writes a state file for a container of the given sandbox, so
// that container.LoadSandbox() finds it.
func writeStateFile(t *testing.T, rootDir, sbID, cid string, status container.Status) {
	t.Helper()
	path := filepath.Join(rootDir, fmt.Sprintf("%s_sandbox:%s.state", cid, sbID))
	state := fmt.Sprintf(`{"id":%q,"status":%q,"sandbox":{"id":%q,"noRootContainer":true}}`, cid, status, sbID)
	if err := os.WriteFile(path, []byte(state), 0644); err != nil {
		t.Fatalf("error writing state file %q: %v", path, err)
	}
}

// TestDeleteRunningRequiresForce checks that deleting a running container
// needs --force, except for a sandbox with no containers running. See
// requireForce.
func TestDeleteRunningRequiresForce(t *testing.T) {
	for _, tc := range []struct {
		name            string
		noRootContainer bool
		// subcontainers holds the status of each container in the sandbox.
		subcontainers []container.Status
		wantErr       bool
	}{
		{name: "regular container", wantErr: true},
		{name: "empty sandbox", noRootContainer: true},
		{name: "created container", noRootContainer: true, subcontainers: []container.Status{container.Created}},
		{name: "stopped container", noRootContainer: true, subcontainers: []container.Status{container.Stopped}},
		{name: "paused container", noRootContainer: true, subcontainers: []container.Status{container.Stopped, container.Paused}, wantErr: true},
		// No sandbox process backs these state files, so the refresh marks the
		// container stopped.
		{name: "stale running container", noRootContainer: true, subcontainers: []container.Status{container.Running}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootDir := t.TempDir()
			conf := &config.Config{RootDir: rootDir}
			const sbID = "sandbox"
			writeStateFile(t, rootDir, sbID, sbID, container.Running)
			for i, status := range tc.subcontainers {
				writeStateFile(t, rootDir, sbID, fmt.Sprintf("cont%d", i), status)
			}

			c := &container.Container{
				ID:     sbID,
				Status: container.Running,
				Sandbox: &sandbox.Sandbox{
					ID:              sbID,
					NoRootContainer: tc.noRootContainer,
				},
			}
			err := requireForce(conf, c)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("requireForce() = %v, wantErr: %t", err, tc.wantErr)
			}
		})
	}
}

// startUnresponsiveSandbox writes the state of a container with the given
// status and for which the sandbox never responds on its control socket.
// Returns the container ID, and a channel closed when the sandbox process
// exits.
func startUnresponsiveSandbox(t *testing.T, rootDir string, status container.Status) (string, <-chan struct{}) {
	t.Helper()
	sockPath := filepath.Join(rootDir, "control.sock")
	sockFD, err := server.CreateSocket(sockPath)
	if err != nil {
		t.Fatalf("error creating control socket: %v", err)
	}
	t.Cleanup(func() { unix.Close(sockFD) })
	if err := unix.Listen(sockFD, 16); err != nil {
		t.Fatalf("error listening on control socket: %v", err)
	}
	proc := exec.Command("/bin/sleep", "1000")
	if err := proc.Start(); err != nil {
		t.Fatalf("error starting fake sandbox process: %v", err)
	}
	t.Cleanup(func() { proc.Process.Kill() })
	exited := make(chan struct{})
	go func() {
		proc.Wait()
		close(exited)
	}()
	const id = "booting"
	path := filepath.Join(rootDir, fmt.Sprintf("%s_sandbox:%s.state", id, id))
	state := fmt.Sprintf(`{"id":%q,"status":%q,"spec":{},"saver":{"rootDir":%q,"id":{"sandboxId":%q,"containerId":%q}},"sandbox":{"id":%q,"pid":%d,"controlSocketPath":%q,"mountHints":{}}}`, id, status, rootDir, id, id, id, proc.Process.Pid, sockPath)
	if err := os.WriteFile(path, []byte(state), 0644); err != nil {
		t.Fatalf("error writing state file %q: %v", path, err)
	}
	return id, exited
}

// checkTeardownBootingSandbox checks that `teardown` returns and kills the
// sandbox process, even if it is unresponsive.
func checkTeardownBootingSandbox(t *testing.T, teardown func(conf *config.Config, f *flag.FlagSet) error) {
	t.Helper()
	rootDir := t.TempDir()
	id, exited := startUnresponsiveSandbox(t, rootDir, container.Created)
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Parse([]string{id})
	if err := teardown(&config.Config{RootDir: rootDir}, f); err != nil {
		t.Fatalf("teardown failed: %v", err)
	}
	<-exited
}

// TestDeleteBootingSandbox checks that deleting a created container always
// does its job, even if the sandbox is unresponsive.
func TestDeleteBootingSandbox(t *testing.T) {
	checkTeardownBootingSandbox(t, func(conf *config.Config, f *flag.FlagSet) error {
		d := Delete{}
		return d.execute(f, conf)
	})
}

// TestKillBootingSandbox checks that killing a created container
// that is in the middle of booting does its job.
func TestKillBootingSandbox(t *testing.T) {
	checkTeardownBootingSandbox(t, func(conf *config.Config, f *flag.FlagSet) error {
		k := Kill{}
		c, err := k.loadContainer(conf, f, container.LoadOpts{})
		if err != nil {
			return err
		}
		return c.SignalContainer(unix.SIGKILL, false)
	})
}

// TestStateBootingSandbox checks that loading container that is in the
// middle of booting doesn't block, and reports it as stopped if its
// sandbox exits.
func TestStateBootingSandbox(t *testing.T) {
	rootDir := t.TempDir()
	id, exited := startUnresponsiveSandbox(t, rootDir, container.Created)
	load := func() *container.Container {
		t.Helper()
		c, err := container.Load(rootDir, container.FullID{ContainerID: id}, container.LoadOpts{ReadOnly: true})
		if err != nil {
			t.Fatalf("error loading container: %v", err)
		}
		return c
	}
	c := load()
	if c.Status != container.Created {
		t.Errorf("got status %v, expected %v", c.Status, container.Created)
	}
	if err := unix.Kill(c.Sandbox.Pid.Load(), unix.SIGKILL); err != nil {
		t.Fatalf("error killing sandbox process: %v", err)
	}
	<-exited
	if got := load().Status; got != container.Stopped {
		t.Errorf("got status %v, expected %v", got, container.Stopped)
	}
}

// TestListUnresponsiveSandbox checks that `runsc list` on an unresponsive
// sandbox still works, even while another command holds its state file lock.
func TestListUnresponsiveSandbox(t *testing.T) {
	rootDir := t.TempDir()
	id, _ := startUnresponsiveSandbox(t, rootDir, container.Running)
	lockFile, err := os.OpenFile(filepath.Join(rootDir, fmt.Sprintf("%s_sandbox:%s.lock", id, id)), os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		t.Fatalf("error opening lock file: %v", err)
	}
	defer lockFile.Close()
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		t.Fatalf("error locking state file: %v", err)
	}
	var out bytes.Buffer
	l := List{format: "text"}
	if err := l.execute(rootDir, &out); err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if !regexp.MustCompile(id + `\s+\d+\s+running`).Match(out.Bytes()) {
		t.Errorf("list output doesn't show %q as running:\n%s", id, out.String())
	}
}

// startFakeSandbox writes the state of a created container with a sandbox
// process that has no control socket.
// It returns the container ID, and a channel closed when the sandbox process
// exits.
// `reusedPID` makes the state contain a different process identity under the
// same PID.
func startFakeSandbox(t *testing.T, rootDir string, reusedPID bool) (string, <-chan struct{}) {
	t.Helper()
	proc := exec.Command("/bin/sleep", "1000")
	if err := proc.Start(); err != nil {
		t.Fatalf("error starting fake sandbox process: %v", err)
	}
	t.Cleanup(func() { proc.Process.Kill() })
	exited := make(chan struct{})
	go func() {
		proc.Wait()
		close(exited)
	}()
	identity, err := specutils.ProcessIdentity(proc.Process.Pid)
	if err != nil {
		t.Fatalf("error getting fake sandbox process identity: %v", err)
	}
	if reusedPID {
		identity = math.MaxUint64
	}
	const id = "booting"
	c := &container.Container{
		ID:     id,
		Status: container.Created,
		Spec:   &specs.Spec{},
		Saver: container.StateFile{
			RootDir: rootDir,
			ID:      container.FullID{SandboxID: id, ContainerID: id},
		},
		Sandbox: &sandbox.Sandbox{
			ID:                id,
			PidIdentity:       identity,
			ControlSocketPath: filepath.Join(rootDir, "control.sock"),
			MountHints:        &sentryapi.PodMountHints{},
		},
	}
	c.Sandbox.Pid.Store(proc.Process.Pid)
	state, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("error marshalling container state: %v", err)
	}
	path := filepath.Join(rootDir, fmt.Sprintf("%s_sandbox:%s.state", id, id))
	if err := os.WriteFile(path, state, 0644); err != nil {
		t.Fatalf("error writing state file %q: %v", path, err)
	}
	return id, exited
}

// TestReadOnlyContainerIsNotWritable checks that a container loaded read-only
// cannot be destroyed.
func TestReadOnlyContainerIsNotWritable(t *testing.T) {
	rootDir := t.TempDir()
	id, _ := startFakeSandbox(t, rootDir, false)
	c, err := container.Load(rootDir, container.FullID{ContainerID: id}, container.LoadOpts{SkipCheck: true, ReadOnly: true})
	if err != nil {
		t.Fatalf("error loading container: %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Errorf("destroying a container loaded read-only didn't panic")
		}
	}()
	c.Destroy()
}

// TestDeleteReusedPID checks that deleting a container doesn't kill a process
// that reused its sandbox's PID.
func TestDeleteReusedPID(t *testing.T) {
	rootDir := t.TempDir()
	id, exited := startFakeSandbox(t, rootDir, true)
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Parse([]string{id})
	d := Delete{}
	if err := d.execute(f, &config.Config{RootDir: rootDir}); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	select {
	case <-exited:
		t.Errorf("delete killed the process that reused the sandbox PID")
	case <-time.After(500 * time.Millisecond):
	}
}
