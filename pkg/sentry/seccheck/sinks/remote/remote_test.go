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

package remote

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/test"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

func waitForFile(path string) error {
	return testutil.Poll(func() error {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return err
			}
			return &backoff.PermanentError{Err: err}
		}
		return nil
	}, 5*time.Second)
}

type syncBuffer struct {
	mu sync.Mutex
	// +checklocks:mu
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type exampleServer struct {
	path string
	cmd  *exec.Cmd
	out  syncBuffer
}

func newExampleServer(quiet bool) (*exampleServer, error) {
	exe, err := testutil.FindFile("examples/seccheck/server_cc")
	if err != nil {
		return nil, fmt.Errorf("error finding server_cc: %v", err)
	}

	dir, err := os.MkdirTemp(os.TempDir(), "remote")
	if err != nil {
		return nil, fmt.Errorf("Setup(%q): %v", dir, err)
	}

	server := &exampleServer{path: filepath.Join(dir, "remote.sock")}
	server.cmd = exec.Command(exe, server.path)
	if quiet {
		server.cmd.Args = append(server.cmd.Args, "-q")
	}
	server.cmd.Stdout = &server.out
	server.cmd.Stderr = &server.out
	if err := server.cmd.Start(); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("error running %q: %v", exe, err)
	}

	if err := waitForFile(server.path); err != nil {
		server.stop()
		return nil, fmt.Errorf("error waiting for server file %q: %w", server.path, err)
	}
	return server, nil
}

func (s *exampleServer) stop() {
	_ = s.cmd.Process.Kill()
	_ = s.cmd.Wait()
	_ = os.Remove(s.path)
}

func TestBasic(t *testing.T) {
	server, err := test.NewServer()
	if err != nil {
		t.Fatalf("newServer(): %v", err)
	}
	defer server.Close()

	endpoint, err := setup(server.Endpoint)
	if err != nil {
		t.Fatalf("setup(): %v", err)
	}
	endpointFD, err := fd.NewFromFile(endpoint)
	if err != nil {
		_ = endpoint.Close()
		t.Fatalf("NewFromFile(): %v", err)
	}
	_ = endpoint.Close()

	r, err := new(nil, endpointFD)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	info := &pb.ExitNotifyParentInfo{ExitStatus: 123}
	if err := r.ExitNotifyParent(nil, seccheck.FieldSet{}, info); err != nil {
		t.Fatalf("ExitNotifyParent: %v", err)
	}

	server.WaitForCount(1)
	pt := server.GetPoints()[0]
	if want := pb.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT; pt.MsgType != want {
		t.Errorf("wrong message type, want: %v, got: %v", want, pt.MsgType)
	}
	got := &pb.ExitNotifyParentInfo{}
	if err := proto.Unmarshal(pt.Msg, got); err != nil {
		t.Errorf("proto.Unmarshal(ExitNotifyParentInfo): %v", err)
	}
	if !proto.Equal(info, got) {
		t.Errorf("Received point is different, want: %+v, got: %+v", info, got)
	}
	// Check that no more points were received.
	if want, got := 1, server.Count(); want != got {
		t.Errorf("wrong number of points, want: %d, got: %d", want, got)
	}
}

func TestVersionUnsupported(t *testing.T) {
	server, err := test.NewServer()
	if err != nil {
		t.Fatalf("newServer(): %v", err)
	}
	defer server.Close()

	server.SetVersion(0)

	_, err = setup(server.Endpoint)
	if err == nil || !strings.Contains(err.Error(), "remote version") {
		t.Fatalf("Wrong error: %v", err)
	}
}

func TestVersionNewer(t *testing.T) {
	server, err := test.NewServer()
	if err != nil {
		t.Fatalf("newServer(): %v", err)
	}
	defer server.Close()

	server.SetVersion(wire.CurrentVersion + 10)

	endpoint, err := setup(server.Endpoint)
	if err != nil {
		t.Fatalf("setup(): %v", err)
	}
	_ = endpoint.Close()
}

// Test that the example C++ server works. It's easier to test from here and
// also changes that can break it will likely originate here.
func TestExample(t *testing.T) {
	server, err := newExampleServer(false)
	if err != nil {
		t.Fatalf("newExampleServer(): %v", err)
	}
	defer server.stop()

	endpoint, err := setup(server.path)
	if err != nil {
		t.Fatalf("setup(): %v", err)
	}
	endpointFD, err := fd.NewFromFile(endpoint)
	if err != nil {
		_ = endpoint.Close()
		t.Fatalf("NewFromFile(): %v", err)
	}
	_ = endpoint.Close()

	r, err := new(nil, endpointFD)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	info := pb.ExitNotifyParentInfo{ExitStatus: 123}
	if err := r.ExitNotifyParent(nil, seccheck.FieldSet{}, &info); err != nil {
		t.Fatalf("ExitNotifyParent: %v", err)
	}
	check := func() error {
		gotRaw := server.out.String()
		// Collapse whitespace.
		got := strings.Join(strings.Fields(gotRaw), " ")
		if !strings.Contains(got, "ExitNotifyParentInfo => exit_status: 123") {
			return fmt.Errorf("ExitNotifyParentInfo point didn't get to the server, out: %q, raw: %q", got, gotRaw)
		}
		return nil
	}
	if err := testutil.Poll(check, time.Second); err != nil {
		t.Errorf(err.Error())
	}
}

func TestConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config map[string]any
		want   *remote
		err    string
	}{
		{
			name:   "default",
			config: map[string]any{},
			want: &remote{
				retries:        0,
				initialBackoff: 25 * time.Microsecond,
				maxBackoff:     10 * time.Millisecond,
			},
		},
		{
			name: "all",
			config: map[string]any{
				"retries":     float64(10),
				"backoff":     "1s",
				"backoff_max": "10s",
			},
			want: &remote{
				retries:        10,
				initialBackoff: time.Second,
				maxBackoff:     10 * time.Second,
			},
		},
		{
			name: "bad-retries",
			config: map[string]any{
				"retries": "10",
			},
			err: "retries",
		},
		{
			name: "bad-backoff",
			config: map[string]any{
				"backoff": "wrong",
			},
			err: "invalid duration",
		},
		{
			name: "bad-backoff-max",
			config: map[string]any{
				"backoff_max": 10,
			},
			err: "is not an string",
		},
		{
			name: "bad-invalid-backoffs",
			config: map[string]any{
				"retries":     float64(10),
				"backoff":     "10s",
				"backoff_max": "1s",
			},
			err: "cannot be larger than max",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var endpoint fd.FD
			sink, err := new(tc.config, &endpoint)
			if len(tc.err) == 0 {
				if err != nil {
					t.Fatalf("new(%q): %v", tc.config, err)
				}
				got := sink.(*remote)
				got.endpoint = nil
				if *got != *tc.want {
					t.Errorf("wrong remote: want: %+v, got: %+v", tc.want, got)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("wrong error: want: %v, got: %v", tc.err, err)
			}
		})
	}
}

func BenchmarkSmall(t *testing.B) {
	// Run server in a separate process just to isolate it as much as possible.
	server, err := newExampleServer(false)
	if err != nil {
		t.Fatalf("newExampleServer(): %v", err)
	}
	defer server.stop()

	endpoint, err := setup(server.path)
	if err != nil {
		t.Fatalf("setup(): %v", err)
	}
	endpointFD, err := fd.NewFromFile(endpoint)
	if err != nil {
		_ = endpoint.Close()
		t.Fatalf("NewFromFile(): %v", err)
	}
	_ = endpoint.Close()

	r, err := new(nil, endpointFD)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	t.ResetTimer()
	t.RunParallel(func(sub *testing.PB) {
		for sub.Next() {
			info := pb.ExitNotifyParentInfo{ExitStatus: 123}
			if err := r.ExitNotifyParent(nil, seccheck.FieldSet{}, &info); err != nil {
				t.Fatalf("ExitNotifyParent: %v", err)
			}
		}
	})
}

func BenchmarkProtoAny(t *testing.B) {
	info := &pb.ExitNotifyParentInfo{ExitStatus: 123}

	t.ResetTimer()
	t.RunParallel(func(sub *testing.PB) {
		for sub.Next() {
			any, err := anypb.New(info)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proto.Marshal(any); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func BenchmarkProtoEnum(t *testing.B) {
	info := &pb.ExitNotifyParentInfo{ExitStatus: 123}

	t.ResetTimer()
	t.RunParallel(func(sub *testing.PB) {
		for sub.Next() {
			if _, err := proto.Marshal(info); err != nil {
				t.Fatal(err)
			}
		}
	})
}
