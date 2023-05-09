// Copyright 2022 The gVisor Authors.
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

// Package trace provides end-to-end integration tests for `runsc trace`.
package trace

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/test"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/trace/config"
)

var cutoffTime time.Time

type checkers struct {
	checker func(test.Message) error
	count   int
}

// TestAll enabled all trace points in the system with all optional and context
// fields enabled. Then it runs a workload that will trigger those points and
// run some basic validation over the points generated.
func TestAll(t *testing.T) {
	server, err := test.NewServer()
	if err != nil {
		t.Fatal(err)
	}

	runsc, err := testutil.FindFile("runsc/runsc")
	if err != nil {
		t.Fatal(err)
	}
	builder := config.Builder{}
	if err := builder.LoadAllPoints(runsc); err != nil {
		t.Fatal(err)
	}
	builder.AddSink(seccheck.SinkConfig{
		Name: "remote",
		Config: map[string]any{
			"endpoint": server.Endpoint,
		},
	})

	cfgFile, err := os.CreateTemp(testutil.TmpDir(), "config")
	if err != nil {
		t.Fatalf("error creating tmp file: %v", err)
	}
	defer cfgFile.Close()
	if err := builder.WriteInitConfig(cfgFile); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	workload, err := testutil.FindFile("test/trace/workload/workload")
	if err != nil {
		t.Fatal(err)
	}
	// No trace point should have a time lesser than this.
	cutoffTime = time.Now()
	cmd := exec.Command(
		runsc,
		"--debug", "--alsologtostderr", // Debug logging for troubleshooting
		"--rootless", "--network=none", "--TESTONLY-unsafe-nonroot", // Disable features that we don't care
		"--pod-init-config", cfgFile.Name(),
		"do", workload)
	out, err := cmd.CombinedOutput()
	t.Log(string(out))
	if err != nil {
		t.Fatalf("runsc do: %v", err)
	}

	// Wait until the sandbox disconnects to ensure all points were gathered.
	server.WaitForNoClients()

	matchers := matchPoints(t, server.GetPoints())
	extraMatchers(t, server.GetPoints(), matchers)
	validatePoints(t, server.GetPoints(), matchers)
}

func matchPoints(t *testing.T, msgs []test.Message) map[pb.MessageType]*checkers {
	// Register functions that verify each available point.
	matchers := map[pb.MessageType]*checkers{
		pb.MessageType_MESSAGE_CONTAINER_START:           {checker: checkContainerStart},
		pb.MessageType_MESSAGE_SENTRY_CLONE:              {checker: checkSentryClone},
		pb.MessageType_MESSAGE_SENTRY_EXEC:               {checker: checkSentryExec},
		pb.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT: {checker: checkSentryExitNotifyParent},
		pb.MessageType_MESSAGE_SENTRY_TASK_EXIT:          {checker: checkSentryTaskExit},
		pb.MessageType_MESSAGE_SYSCALL_CLOSE:             {checker: checkSyscallClose},
		pb.MessageType_MESSAGE_SYSCALL_CONNECT:           {checker: checkSyscallConnect},
		pb.MessageType_MESSAGE_SYSCALL_EXECVE:            {checker: checkSyscallExecve},
		pb.MessageType_MESSAGE_SYSCALL_OPEN:              {checker: checkSyscallOpen},
		pb.MessageType_MESSAGE_SYSCALL_RAW:               {checker: checkSyscallRaw},
		pb.MessageType_MESSAGE_SYSCALL_READ:              {checker: checkSyscallRead},
		pb.MessageType_MESSAGE_SYSCALL_SOCKET:            {checker: checkSyscallSocket},
		pb.MessageType_MESSAGE_SYSCALL_WRITE:             {checker: checkSyscallWrite},
		pb.MessageType_MESSAGE_SYSCALL_CHDIR:             {checker: checkSyscallChdir},
		pb.MessageType_MESSAGE_SYSCALL_SETID:             {checker: checkSyscallSetid},
		pb.MessageType_MESSAGE_SYSCALL_SETRESID:          {checker: checkSyscallSetresid},
		pb.MessageType_MESSAGE_SYSCALL_CHROOT:            {checker: checkSyscallChroot},
		pb.MessageType_MESSAGE_SYSCALL_DUP:               {checker: checkSyscallDup},
		pb.MessageType_MESSAGE_SYSCALL_PRLIMIT64:         {checker: checkSyscallPrlimit64},
		pb.MessageType_MESSAGE_SYSCALL_EVENTFD:           {checker: checkSyscallEventfd},
		pb.MessageType_MESSAGE_SYSCALL_SIGNALFD:          {checker: checkSyscallSignalfd},
		pb.MessageType_MESSAGE_SYSCALL_BIND:              {checker: checkSyscallBind},
		pb.MessageType_MESSAGE_SYSCALL_ACCEPT:            {checker: checkSyscallAccept},
		pb.MessageType_MESSAGE_SYSCALL_FCNTL:             {checker: checkSyscallFcntl},
		pb.MessageType_MESSAGE_SYSCALL_PIPE:              {checker: checkSyscallPipe},
		pb.MessageType_MESSAGE_SYSCALL_TIMERFD_CREATE:    {checker: checkSyscallTimerfdCreate},
		pb.MessageType_MESSAGE_SYSCALL_TIMERFD_SETTIME:   {checker: checkSyscallTimerfdSettime},
		pb.MessageType_MESSAGE_SYSCALL_TIMERFD_GETTIME:   {checker: checkSyscallTimerfdGettime},
		pb.MessageType_MESSAGE_SYSCALL_INOTIFY_INIT:      {checker: checkSyscallInotifyInit},
		pb.MessageType_MESSAGE_SYSCALL_INOTIFY_ADD_WATCH: {checker: checkSyscallInotifyInitAddWatch},
		pb.MessageType_MESSAGE_SYSCALL_INOTIFY_RM_WATCH:  {checker: checkSyscallInotifyInitRmWatch},
		pb.MessageType_MESSAGE_SYSCALL_CLONE:             {checker: checkSyscallClone},
	}
	return matchers
}

func validatePoints(t *testing.T, msgs []test.Message, matchers map[pb.MessageType]*checkers) {
	for _, msg := range msgs {
		t.Logf("Processing message type %v", msg.MsgType)
		if handler := matchers[msg.MsgType]; handler == nil {
			// All points generated should have a corresponding matcher.
			t.Errorf("No matcher for message type %v", msg.MsgType)
		} else {
			handler.count++
			if err := handler.checker(msg); err != nil {
				t.Errorf("message type %v: %v", msg.MsgType, err)
			}
		}
	}
	for msgType, match := range matchers {
		t.Logf("Processed %d messages for %v", match.count, msgType)
		if match.count == 0 {
			// All matchers should be triggered at least once to ensure points are
			// firing with the workload.
			t.Errorf("no point was generated for %v", msgType)
		}
	}
}

func checkTimeNs(ns int64) error {
	if ns <= int64(cutoffTime.Nanosecond()) {
		return fmt.Errorf("time: got: %d (%v), should not be less than %d (%v)", ns, time.Unix(0, ns), cutoffTime.Nanosecond(), cutoffTime)
	}
	return nil
}

type contextDataOpts struct {
	skipCwd bool
}

func checkContextData(data *pb.ContextData) error {
	return checkContextDataOpts(data, contextDataOpts{})
}

func checkContextDataOpts(data *pb.ContextData, opts contextDataOpts) error {
	if data == nil {
		return fmt.Errorf("ContextData should not be nil")
	}
	if !strings.HasPrefix(data.ContainerId, "runsc-") {
		return fmt.Errorf("invalid container ID %q", data.ContainerId)
	}

	if err := checkTimeNs(data.TimeNs); err != nil {
		return err
	}
	if err := checkTimeNs(data.ThreadStartTimeNs); err != nil {
		return err
	}
	if data.ThreadStartTimeNs > data.TimeNs {
		return fmt.Errorf("thread_start_time should not be greater than point time: %d (%v), got: %d (%v)", data.TimeNs, time.Unix(0, data.TimeNs), data.ThreadStartTimeNs, time.Unix(0, data.ThreadStartTimeNs))
	}
	if err := checkTimeNs(data.ThreadGroupStartTimeNs); err != nil {
		return err
	}
	if data.ThreadGroupStartTimeNs > data.TimeNs {
		return fmt.Errorf("thread_group_start_time should not be greater than point time: %d (%v), got: %d (%v)", data.TimeNs, time.Unix(0, data.TimeNs), data.ThreadGroupStartTimeNs, time.Unix(0, data.ThreadGroupStartTimeNs))
	}

	if data.ThreadId <= 0 {
		return fmt.Errorf("invalid thread_id: %v", data.ThreadId)
	}
	if data.ThreadGroupId <= 0 {
		return fmt.Errorf("invalid thread_group_id: %v", data.ThreadGroupId)
	}
	if !opts.skipCwd && len(data.Cwd) == 0 {
		return fmt.Errorf("invalid cwd: %v", data.Cwd)
	}
	if len(data.ProcessName) == 0 {
		return fmt.Errorf("invalid process_name: %v", data.ProcessName)
	}
	return nil
}

func checkContainerStart(msg test.Message) error {
	p := pb.Start{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if !strings.HasPrefix(p.Id, "runsc-") {
		return fmt.Errorf("invalid container ID %q", p.Id)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("Getwd(): %v", err)
	}
	if cwd != p.Cwd {
		return fmt.Errorf("invalid cwd, want: %q, got: %q", cwd, p.Cwd)
	}
	if len(p.Args) == 0 {
		return fmt.Errorf("empty args")
	}
	if len(p.Env) == 0 {
		return fmt.Errorf("empty env")
	}
	for _, e := range p.Env {
		if strings.IndexRune(e, '=') == -1 {
			return fmt.Errorf("malformed env: %q", e)
		}
	}
	if p.Terminal {
		return fmt.Errorf("terminal should be off")
	}
	return nil
}

func checkSentryTaskExit(msg test.Message) error {
	p := pb.TaskExit{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	return nil
}

func checkSyscallRaw(msg test.Message) error {
	p := pb.Syscall{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	// Sanity check that Sysno is within valid range. If sysno could be larger
	// than the value below, update it accordingly.
	if p.Sysno > 500 {
		return fmt.Errorf("invalid syscall number %d", p.Sysno)
	}
	return nil
}

func checkSyscallClose(msg test.Message) error {
	p := pb.Close{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd < 0 {
		// Although negative FD is possible, it doesn't happen in the test.
		return fmt.Errorf("closing negative FD: %d", p.Fd)
	}
	return nil
}

func checkSyscallOpen(msg test.Message) error {
	p := pb.Open{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	return nil
}

func checkSyscallRead(msg test.Message) error {
	p := pb.Read{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd < 0 {
		// Although negative FD is possible, it doesn't happen in the test.
		return fmt.Errorf("read negative FD: %d", p.Fd)
	}
	if p.HasOffset {
		// Workload always uses 20 for read offsets (account for partial reads).
		if lower, upper := int64(20), int64(120); p.Offset < lower && p.Offset > upper {
			return fmt.Errorf("invalid offset, want: [%d, %d], got: %d", lower, upper, p.Offset)
		}
	} else if p.Offset != 0 {
		return fmt.Errorf("offset should be 0: %+v", &p)
	}
	if p.Flags != 0 && p.Flags != unix.RWF_HIPRI {
		return fmt.Errorf("invalid flag value, want: 0 || RWF_HIPRI, got: %+x", p.Flags)
	}
	return nil
}

func checkSyscallWrite(msg test.Message) error {
	p := pb.Write{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd < 0 {
		// Although negative FD is possible, it doesn't happen in the test.
		return fmt.Errorf("write negative FD: %d", p.Fd)
	}
	if p.HasOffset {
		// Workload always uses 10 for write offsets (account for partial writes).
		if lower, upper := int64(10), int64(110); p.Offset < lower && p.Offset > upper {
			return fmt.Errorf("invalid offset, want: [%d, %d], got: %d", lower, upper, p.Offset)
		}
	} else if p.Offset != 0 {
		return fmt.Errorf("offset should be 0: %+v", &p)
	}
	if p.Flags != 0 && p.Flags != unix.RWF_HIPRI {
		return fmt.Errorf("invalid flag value, want: 0 || RWF_HIPRI, got: %+x", p.Flags)
	}
	return nil
}

func checkSentryClone(msg test.Message) error {
	p := pb.CloneInfo{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.CreatedThreadId < 0 {
		return fmt.Errorf("invalid TID: %d", p.CreatedThreadId)
	}
	if p.CreatedThreadGroupId < 0 {
		return fmt.Errorf("invalid TGID: %d", p.CreatedThreadGroupId)
	}
	if p.CreatedThreadStartTimeNs < 0 {
		return fmt.Errorf("invalid TID: %d", p.CreatedThreadId)
	}
	return checkTimeNs(p.CreatedThreadStartTimeNs)
}

func checkSentryExec(msg test.Message) error {
	p := pb.ExecveInfo{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	// As test runs locally the binary path may resolve to a symlink so would not be exactly same
	// as the pathname passed.
	if want := "/bin/true"; !strings.Contains(p.BinaryPath, want) {
		return fmt.Errorf("wrong BinaryPath, want: %q, got: %q", want, p.BinaryPath)
	}
	if len(p.Argv) == 0 {
		return fmt.Errorf("empty Argv")
	}
	if !strings.Contains(p.BinaryPath, p.Argv[0]) {
		return fmt.Errorf("wrong Argv[0], want: %q, got: %q", p.BinaryPath, p.Argv[0])
	}
	if len(p.Env) == 0 {
		return fmt.Errorf("empty Env")
	}
	if want := "TEST=123"; want != p.Env[0] {
		return fmt.Errorf("wrong Env[0], want: %q, got: %q", want, p.Env[0])
	}
	if (p.BinaryMode & 0111) == 0 {
		return fmt.Errorf("executing non-executable file, mode: %#o (%#x)", p.BinaryMode, p.BinaryMode)
	}
	const nobody = 65534
	if p.BinaryUid != nobody {
		return fmt.Errorf("BinaryUid, want: %d, got: %d", nobody, p.BinaryUid)
	}
	if p.BinaryGid != nobody {
		return fmt.Errorf("BinaryGid, want: %d, got: %d", nobody, p.BinaryGid)
	}
	return nil
}

func checkSyscallExecve(msg test.Message) error {
	p := pb.Execve{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd < 3 {
		return fmt.Errorf("execve invalid FD: %d", p.Fd)
	}
	if want := "/"; want != p.FdPath {
		return fmt.Errorf("wrong FdPath, want: %q, got: %q", want, p.FdPath)
	}
	if want := "/bin/true"; want != p.Pathname {
		return fmt.Errorf("wrong Pathname, want: %q, got: %q", want, p.Pathname)
	}
	if len(p.Argv) == 0 {
		return fmt.Errorf("empty Argv")
	}
	if p.Argv[0] != p.Pathname {
		return fmt.Errorf("wrong Argv[0], want: %q, got: %q", p.Pathname, p.Argv[0])
	}
	if len(p.Envv) == 0 {
		return fmt.Errorf("empty Envv")
	}
	if want := "TEST=123"; want != p.Envv[0] {
		return fmt.Errorf("wrong Envv[0], want: %q, got: %q", want, p.Envv[0])
	}
	return nil
}

func checkSentryExitNotifyParent(msg test.Message) error {
	p := pb.ExitNotifyParentInfo{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	// cwd is empty because the task has already been destroyed when the point
	// fires.
	opts := contextDataOpts{skipCwd: true}
	if err := checkContextDataOpts(p.ContextData, opts); err != nil {
		return err
	}
	if p.ExitStatus != 0 {
		return fmt.Errorf("wrong ExitStatus, want: 0, got: %d", p.ExitStatus)
	}
	return nil
}

func checkSyscallConnect(msg test.Message) error {
	p := pb.Connect{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd < 3 {
		return fmt.Errorf("invalid FD: %d", p.Fd)
	}
	if want := "socket:"; !strings.HasPrefix(p.FdPath, want) {
		return fmt.Errorf("FdPath should start with %q, got: %q", want, p.FdPath)
	}
	if len(p.Address) == 0 {
		return fmt.Errorf("empty address: %q", string(p.Address))
	}

	return nil
}

func checkSyscallSocket(msg test.Message) error {
	p := pb.Socket{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if want := unix.AF_UNIX; int32(want) != p.Domain {
		return fmt.Errorf("wrong Domain, want: %v, got: %v", want, p.Domain)
	}
	if want := unix.SOCK_STREAM; int32(want) != p.Type {
		return fmt.Errorf("wrong Type, want: %v, got: %v", want, p.Type)
	}
	if want := int32(0); want != p.Protocol {
		return fmt.Errorf("wrong Protocol, want: %v, got: %v", want, p.Protocol)
	}

	return nil
}

func checkSyscallSetid(msg test.Message) error {
	p := pb.Setid{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Id != 0 {
		return fmt.Errorf("invalid id: %d", p.Id)
	}

	return nil
}

func checkSyscallSetresid(msg test.Message) error {
	p := pb.Setresid{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.GetRid() != 0 {
		return fmt.Errorf("invalid rid: %d", p.Rid)
	}
	if p.GetEid() != 0 {
		return fmt.Errorf("invalid eid: %d", p.Eid)
	}
	if p.GetSid() != 0 {
		return fmt.Errorf("invalid sid: %d", p.Sid)
	}

	return nil
}

func checkSyscallChdir(msg test.Message) error {
	p := pb.Chdir{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd < 3 && p.Fd != unix.AT_FDCWD { // Constant used for all file-related syscalls.
		return fmt.Errorf("invalid FD: %d", p.Fd)
	}
	if want := "trace_test.abc"; !strings.Contains(p.Pathname, want) {
		return fmt.Errorf("wrong Pathname, got: %q, want: %q", p.Pathname, want)
	}

	return nil
}

func checkSyscallDup(msg test.Message) error {
	p := pb.Dup{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.OldFd < 0 {
		return fmt.Errorf("invalid fd: %d", p.OldFd)
	}
	if p.NewFd < 0 {
		return fmt.Errorf("invalid fd: %d", p.NewFd)
	}
	if p.Flags != unix.O_CLOEXEC && p.Flags != 0 {
		return fmt.Errorf("invalid flag got: %v", p.Flags)
	}

	return nil
}

func checkSyscallPrlimit64(msg test.Message) error {
	p := pb.Prlimit{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Pid < 0 {
		return fmt.Errorf("invalid pid: %d", p.Pid)
	}
	return nil
}

func checkSyscallEventfd(msg test.Message) error {
	p := pb.Eventfd{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Val < 0 {
		return fmt.Errorf("invalid pid: %d", p.Val)
	}
	if p.Flags != unix.EFD_NONBLOCK && p.Flags != 0 {
		return fmt.Errorf("invalid flag got: %d, ", p.Flags)
	}

	return nil
}

func checkSyscallBind(msg test.Message) error {
	p := pb.Bind{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd < 0 {
		return fmt.Errorf("invalid fd: %d", p.Fd)
	}
	if p.FdPath == " " {
		return fmt.Errorf("invalid path: %v", p.FdPath)
	}
	if len(p.Address) == 0 {
		return fmt.Errorf("invalid address: %d", p.Address)
	}
	return nil
}

func checkSyscallAccept(msg test.Message) error {
	p := pb.Accept{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd < 0 {
		return fmt.Errorf("invalid fd: %d", p.Fd)
	}
	if p.FdPath == "" {
		return fmt.Errorf("invalid path: %v", p.FdPath)
	}
	if len(p.Address) != 0 {
		return fmt.Errorf("invalid address: %d, %v", p.Address, p.Sysno)
	}
	if p.Flags != 0 && p.Flags != unix.SOCK_CLOEXEC {
		return fmt.Errorf("invalid flag got: %d", p.Flags)
	}
	return nil
}

func checkSyscallChroot(msg test.Message) error {
	p := pb.Chroot{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if want := "trace_test.abc"; !strings.Contains(p.Pathname, want) {
		return fmt.Errorf("wrong pathname, want: %q, got: %q", want, p.Pathname)
	}

	return nil
}

func checkSyscallFcntl(msg test.Message) error {
	p := pb.Fcntl{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd < 0 {
		return fmt.Errorf("invalid fd: %d", p.Fd)
	}
	if p.Cmd != unix.F_GETFL {
		return fmt.Errorf("invalid cmd:  got: %v, want: F_GETFL", p.Cmd)
	}
	return nil
}

func checkSyscallPipe(msg test.Message) error {
	p := pb.Pipe{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Reader < 0 {
		return fmt.Errorf("invalid reader fd: %d", p.Reader)
	}
	if p.Writer < 0 {
		return fmt.Errorf("invalid writer fd: %d", p.Writer)
	}
	if p.Flags != unix.O_CLOEXEC && p.Flags != 0 {
		return fmt.Errorf("invalid flag got: %v", p.Flags)
	}
	return nil
}

func checkSyscallSignalfd(msg test.Message) error {
	p := pb.Signalfd{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd != -1 {
		return fmt.Errorf("invalid fd: %d", p.Fd)
	}
	if p.Sigset != 0 && p.Sigset != uint64(unix.SIGILL) {
		return fmt.Errorf("invalid signal got: %v", p.Sigset)
	}
	return checkSyscallSignalfdFlags(p.Flags)
}

func checkSyscallTimerfdCreate(msg test.Message) error {
	p := pb.TimerfdCreate{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.ClockId != unix.CLOCK_REALTIME {
		return fmt.Errorf("invalid clockid: %d", p.ClockId)
	}
	if p.Flags != 0 {
		return fmt.Errorf("invalid flag got: %v", p.Flags)
	}
	return nil
}

func checkSyscallTimerfdSettime(msg test.Message) error {
	p := pb.TimerfdSetTime{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd < 0 {
		return fmt.Errorf("invalid clockid: %d", p.Fd)
	}
	if p.FdPath == "" {
		return fmt.Errorf("invalid path: %q", p.FdPath)
	}
	if p.Flags != unix.TFD_TIMER_ABSTIME {
		return fmt.Errorf("invalid flag got: %v", p.Flags)
	}
	if p.OldValue != nil {
		return fmt.Errorf("invalid oldvalue: %v", p.OldValue.String())
	}
	if p.NewValue == nil {
		return fmt.Errorf("invalid oldvalue: %v", p.OldValue.String())
	}
	return nil
}

func checkSyscallTimerfdGettime(msg test.Message) error {
	p := pb.TimerfdGetTime{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd < 0 {
		return fmt.Errorf("invalid clockid: %d", p.Fd)
	}
	if p.FdPath == "" {
		return fmt.Errorf("invalid path: %q", p.FdPath)
	}
	if p.CurValue == nil {
		return fmt.Errorf("invalid oldvalue: %v", p.CurValue.String())
	}
	return nil
}

func checkSyscallClone(msg test.Message) error {
	p := pb.Clone{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	// Flags used by default in system calls that use clone(2) in the underying.
	rawFlags := unix.CLONE_CHILD_CLEARTID | unix.CLONE_CHILD_SETTID | uint64(unix.SIGCHLD)
	// Flags used for clone(2) syscall in workload.cc
	cloneFlags := uint64(unix.SIGCHLD) | unix.CLONE_VFORK | unix.CLONE_FILES
	if p.Flags != uint64(rawFlags) && p.Flags != cloneFlags {
		return fmt.Errorf("invalid flag got: %v", p.Flags)
	}
	if (p.Flags == uint64(rawFlags) && p.Stack != 0) || (p.Flags == cloneFlags && p.Stack == 0) {
		return fmt.Errorf("invalid stack got: %v", p.Stack)
	}
	return nil
}

func checkSyscallInotifyInit(msg test.Message) error {
	p := pb.InotifyInit{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if !(p.Flags == 0 || p.Flags == unix.IN_NONBLOCK) {
		return fmt.Errorf("invalid flag got: %v", p.Flags)
	}
	return nil
}

func checkSyscallInotifyInitAddWatch(msg test.Message) error {
	p := pb.InotifyAddWatch{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd < 0 {
		return fmt.Errorf("invalid fd: %d", p.Fd)
	}
	if p.FdPath == "" {
		return fmt.Errorf("invalid path: %v", p.FdPath)
	}
	if want := "timer_trace_test.abc"; !strings.Contains(p.Pathname, want) {
		return fmt.Errorf("wrong pathname, got: %q, want: %q", p.Pathname, want)
	}
	if want := unix.IN_NONBLOCK; want != int(p.Mask) {
		return fmt.Errorf("invalid mask: want: %v, got:%v", want, p.Mask)
	}
	return nil
}

func checkSyscallInotifyInitRmWatch(msg test.Message) error {
	p := pb.InotifyRmWatch{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	if p.Fd < 0 {
		return fmt.Errorf("invalid fd: %d", p.Fd)
	}
	if p.FdPath == "" {
		return fmt.Errorf("invalid path: %q", p.FdPath)
	}
	if p.Wd < 0 {
		return fmt.Errorf("invalid wd: %d", p.Wd)
	}
	return nil
}
