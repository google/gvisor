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

package root

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestSandboxPidfdHandoff(t *testing.T) {
	for _, tc := range []struct {
		name          string
		noReceiver    bool
		badPIDFile    bool
		wantErrorText string
	}{
		{name: "created"},
		{name: "missing-receiver", noReceiver: true, wantErrorText: "connecting to pidfd socket"},
		{name: "failed-after-handoff", badPIDFile: true, wantErrorText: "error writing PID file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := config.NewFromFlags(flag.CommandLine)
			if err != nil {
				t.Fatal(err)
			}
			conf.Network = config.NetworkNone
			conf.IgnoreCgroups = true
			if err := conf.Overlay2.Set("none"); err != nil {
				t.Fatal(err)
			}
			_, bundle, cleanup, err := testutil.SetupContainer(testutil.NewSpecWithArgs("/bin/true"), conf)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(cleanup)
			id := testutil.RandomContainerID()
			t.Cleanup(func() {
				_, _ = pidfdRunsc(t, conf, "delete", "--force", id)
				checkPidfdProcessesGone(t, id)
			})

			// Bazel's temporary paths may exceed the Unix socket path limit.
			dir, err := os.MkdirTemp("", "runsc-pidfd-test")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			socketPath := filepath.Join(dir, "socket")
			var listener *net.UnixListener
			if !tc.noReceiver {
				listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
			}
			pidFile := filepath.Join(bundle, "init.pid")
			if tc.badPIDFile {
				// PID-file creation follows the handoff and exercises rollback
				// while the receiver still holds the sandbox's descriptor.
				pidFile = filepath.Join(bundle, "absent", "init.pid")
			}
			out, err := pidfdRunsc(t, conf, "create", "--bundle", bundle, "--pid-file", pidFile, "--pidfd-socket", socketPath, id)
			if tc.wantErrorText == "" {
				if err != nil {
					t.Fatalf("runsc create: %v\n%s", err, out)
				}
			} else if err == nil || !strings.Contains(string(out), tc.wantErrorText) {
				t.Fatalf("runsc create: %v\n%s\nwant error containing %q", err, out, tc.wantErrorText)
			}

			if !tc.noReceiver {
				fd := receivePidfd(t, listener)
				if !tc.badPIDFile {
					c, err := container.Load(conf.RootDir, container.FullID{SandboxID: id, ContainerID: id}, container.LoadOpts{Exact: true, SkipCheck: true, ReadOnly: true})
					if err != nil {
						t.Fatal(err)
					}
					info, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
					if err != nil {
						t.Fatal(err)
					}
					if want := fmt.Sprintf("Pid:\t%d\n", c.Sandbox.Getpid()); !strings.Contains(string(info), want) {
						t.Fatalf("received descriptor does not identify sandbox %d:\n%s", c.Sandbox.Getpid(), info)
					}
					poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
					if n, err := unix.Poll(poll, 0); err != nil || n != 0 {
						t.Fatalf("created sandbox pidfd is ready: poll=(%d, %v)", n, err)
					}
					if out, err := pidfdRunsc(t, conf, "delete", "--force", id); err != nil {
						t.Fatalf("runsc delete: %v\n%s", err, out)
					}
				}
				poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				if n, err := unix.Poll(poll, 5000); err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
					t.Fatalf("sandbox survived cleanup: poll=(%d, %v), revents=%#x", n, err, poll[0].Revents)
				}
			}
			if ids, err := container.List(conf.RootDir); err != nil || len(ids) != 0 {
				t.Fatalf("container state remains after cleanup: %v, %v", ids, err)
			}
			checkPidfdProcessesGone(t, id)
		})
	}
}

func pidfdRunsc(t *testing.T, conf *config.Config, args ...string) ([]byte, error) {
	t.Helper()
	output, err := os.CreateTemp(conf.RootDir, "runsc-output")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	defer os.Remove(output.Name())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, specutils.ExePath, append(conf.ToFlags(), args...)...)
	// A created sandbox retains its output descriptors. Use a file so waiting
	// for the creator does not also wait for the sandbox to close a pipe.
	cmd.Stdout, cmd.Stderr = output, output
	err = cmd.Run()
	data, readErr := os.ReadFile(output.Name())
	if readErr != nil {
		t.Fatal(readErr)
	}
	return data, err
}

func receivePidfd(t *testing.T, listener *net.UnixListener) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	data, control := make([]byte, 16), make([]byte, unix.CmsgSpace(4))
	n, controlLen, flags, _, err := conn.ReadMsgUnix(data, control)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := unix.ParseSocketControlMessage(control[:controlLen])
	if err != nil {
		t.Fatal(err)
	}
	var fds []int
	for _, message := range messages {
		rights, err := unix.ParseUnixRights(&message)
		if err != nil {
			t.Fatal(err)
		}
		for _, fd := range rights {
			unix.CloseOnExec(fd)
			t.Cleanup(func() { _ = unix.Close(fd) })
			fds = append(fds, fd)
		}
	}
	if n == 0 || flags&unix.MSG_CTRUNC != 0 || len(fds) != 1 {
		t.Fatalf("pidfd handoff: data=%q flags=%#x descriptors=%v", data[:n], flags, fds)
	}
	return fds[0]
}

func checkPidfdProcessesGone(t *testing.T, id string) {
	t.Helper()
	paths, err := filepath.Glob("/proc/[0-9]*/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue // Processes may exit while /proc is inspected.
		}
		args := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
		if args[len(args)-1] != id {
			continue
		}
		t.Errorf("container process remains after cleanup: %s: %q", path, args)
		pid, err := strconv.Atoi(filepath.Base(filepath.Dir(path)))
		if err != nil {
			t.Fatal(err)
		}
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			continue
		}
		// Limit failure cleanup to the same test-owned process after pinning it.
		if current, err := os.ReadFile(path); err == nil && string(current) == string(data) {
			_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		}
		_ = unix.Close(fd)
	}
}
