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
		Config: map[string]interface{}{
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
		"--rootless", "--network=none", // Disable features that we don't care
		"--pod-init-config", cfgFile.Name(),
		"do", workload)
	out, err := cmd.CombinedOutput()
	t.Log(string(out))
	if err != nil {
		t.Fatalf("runsc do: %v", err)
	}

	// Wait until the sandbox disconnects to ensure all points were gathered.
	server.WaitForNoClients()
	matchPoints(t, server.GetPoints())
}

func matchPoints(t *testing.T, msgs []test.Message) {
	// Register functions that verify each available point.
	matchers := map[pb.MessageType]*struct {
		checker func(test.Message) error
		count   int
	}{
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

		// TODO(gvisor.dev/issue/4805): Add validation for these messages.
		pb.MessageType_MESSAGE_SYSCALL_ACCEPT:    {checker: checkTODO},
		pb.MessageType_MESSAGE_SYSCALL_BIND:      {checker: checkTODO},
		pb.MessageType_MESSAGE_SYSCALL_CLONE:     {checker: checkTODO},
		pb.MessageType_MESSAGE_SYSCALL_DUP:       {checker: checkTODO},
		pb.MessageType_MESSAGE_SYSCALL_PIPE:      {checker: checkTODO},
		pb.MessageType_MESSAGE_SYSCALL_PRLIMIT64: {checker: checkTODO},
	}
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
		return fmt.Errorf("time should not be less than %d (%v), got: %d (%v)", cutoffTime.Nanosecond(), cutoffTime, ns, time.Unix(0, ns))
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
		return fmt.Errorf("reading negative FD: %d", p.Fd)
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
	if want := "/bin/true"; want != p.BinaryPath {
		return fmt.Errorf("wrong BinaryPath, want: %q, got: %q", want, p.BinaryPath)
	}
	if len(p.Argv) == 0 {
		return fmt.Errorf("empty Argv")
	}
	if p.Argv[0] != p.BinaryPath {
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

func checkTODO(_ test.Message) error {
	return nil
}
