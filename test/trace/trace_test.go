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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/checkers/remote/test"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/boot"
)

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
	cfg, err := buildPodConfig(runsc, server.Path)
	if err != nil {
		t.Fatal(err)
	}

	cfgFile, err := ioutil.TempFile(testutil.TmpDir(), "config")
	if err != nil {
		t.Fatalf("error creating tmp file: %v", err)
	}
	defer cfgFile.Close()
	encoder := json.NewEncoder(cfgFile)
	if err := encoder.Encode(&cfg); err != nil {
		t.Fatalf("JSON encode: %v", err)
	}

	workload, err := testutil.FindFile("test/trace/workload/workload")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(
		runsc,
		"--debug", "--alsologtostderr", // Debug logging for troubleshooting
		"--rootless", "--network=none", // Disable features that we don't care
		"--pod-init-config", cfgFile.Name(),
		"do", workload)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("runsc do: %v", err)
	}
	t.Log(string(out))

	// Wait until the sandbox disconnects to ensure all points were gathered.
	server.WaitForNoClients()
	matchPoints(t, server.GetPoints())
}

func buildPodConfig(runscPath, endpoint string) (*boot.InitConfig, error) {
	pts, err := allPoints(runscPath)
	if err != nil {
		return nil, err
	}
	return &boot.InitConfig{
		TraceSession: seccheck.SessionConfig{
			Name:   seccheck.DefaultSessionName,
			Points: pts,
			Sinks: []seccheck.SinkConfig{
				{
					Name: "remote",
					Config: map[string]interface{}{
						"endpoint": endpoint,
					},
				},
			},
		},
	}, nil
}

func allPoints(runscPath string) ([]seccheck.PointConfig, error) {
	cmd := exec.Command(runscPath, "trace", "metadata")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	// The command above produces an output like the following:
	//   POINTS (907)
	//   Name: container/start, optional fields: [], context fields: [time|thread_id]
	scanner := bufio.NewScanner(bytes.NewReader(out))
	if !scanner.Scan() {
		return nil, fmt.Errorf("%q returned empty", cmd)
	}
	if !scanner.Scan() {
		return nil, fmt.Errorf("%q returned empty", cmd)
	}
	var points []seccheck.PointConfig
	for line := scanner.Text(); scanner.Scan(); line = scanner.Text() {
		elems := strings.Split(line, ",")
		if len(elems) != 3 {
			return nil, fmt.Errorf("invalid line: %q", line)
		}
		name := strings.TrimPrefix(elems[0], "Name: ")
		optFields, err := parseFields(elems[1], "optional fields: ")
		if err != nil {
			return nil, err
		}
		ctxFields, err := parseFields(elems[2], "context fields: ")
		if err != nil {
			return nil, err
		}
		points = append(points, seccheck.PointConfig{
			Name:           name,
			OptionalFields: optFields,
			ContextFields:  ctxFields,
		})
	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}
	return points, nil
}

func parseFields(elem, prefix string) ([]string, error) {
	stripped := strings.TrimPrefix(strings.TrimSpace(elem), prefix)
	switch {
	case len(stripped) < 2:
		return nil, fmt.Errorf("invalid %s format: %q", prefix, elem)
	case len(stripped) == 2:
		return nil, nil
	}
	// Remove [] from `stripped`.
	clean := stripped[1 : len(stripped)-1]
	return strings.Split(clean, "|"), nil
}

func matchPoints(t *testing.T, msgs []test.Message) {
	// Register functions that verify each available point.
	matchers := map[pb.MessageType]*struct {
		checker func(test.Message) error
		count   int
	}{
		pb.MessageType_MESSAGE_CONTAINER_START:  {checker: checkContainerStart},
		pb.MessageType_MESSAGE_SENTRY_TASK_EXIT: {checker: checkSentryTaskExit},
		pb.MessageType_MESSAGE_SYSCALL_RAW:      {checker: checkSyscallRaw},
		pb.MessageType_MESSAGE_SYSCALL_OPEN:     {checker: checkSyscallOpen},
		pb.MessageType_MESSAGE_SYSCALL_CLOSE:    {checker: checkSyscallClose},
		pb.MessageType_MESSAGE_SYSCALL_READ:     {checker: checkSyscallRead},
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

func checkContextData(data *pb.ContextData) error {
	if data == nil {
		return fmt.Errorf("ContextData should not be nil")
	}
	if !strings.HasPrefix(data.ContainerId, "runsc-") {
		return fmt.Errorf("invalid container ID %q", data.ContainerId)
	}

	cutoff := time.Now().Add(-time.Minute)
	if data.TimeNs <= int64(cutoff.Nanosecond()) {
		return fmt.Errorf("time should not be less than %d (%v), got: %d (%v)", cutoff.Nanosecond(), cutoff, data.TimeNs, time.Unix(0, data.TimeNs))
	}
	if data.ThreadStartTimeNs <= int64(cutoff.Nanosecond()) {
		return fmt.Errorf("thread_start_time should not be less than %d (%v), got: %d (%v)", cutoff.Nanosecond(), cutoff, data.ThreadStartTimeNs, time.Unix(0, data.ThreadStartTimeNs))
	}
	if data.ThreadStartTimeNs > data.TimeNs {
		return fmt.Errorf("thread_start_time should not be greater than point time: %d (%v), got: %d (%v)", data.TimeNs, time.Unix(0, data.TimeNs), data.ThreadStartTimeNs, time.Unix(0, data.ThreadStartTimeNs))
	}
	if data.ThreadGroupStartTimeNs <= int64(cutoff.Nanosecond()) {
		return fmt.Errorf("thread_group_start_time should not be less than %d (%v), got: %d (%v)", cutoff.Nanosecond(), cutoff, data.ThreadGroupStartTimeNs, time.Unix(0, data.ThreadGroupStartTimeNs))
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
	if len(data.Cwd) == 0 {
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
