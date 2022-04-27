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
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sync"
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

type exampleServer struct {
	path string
	cmd  *exec.Cmd
	out  bytes.Buffer
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

type server struct {
	path   string
	fd     *fd.FD
	stopCh chan struct{}

	mu sync.Mutex
	// +checklocks:mu
	points []*anypb.Any
}

func newServer() (*server, error) {
	dir, err := ioutil.TempDir(os.TempDir(), "remote")
	if err != nil {
		return nil, err
	}
	server, err := newServerPath(filepath.Join(dir, "remote.sock"))
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return server, nil
}

func newServerPath(path string) (*server, error) {
	socket, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_UNIX, SOCK_SEQPACKET, 0): %w", err)
	}
	cu := cleanup.Make(func() {
		_ = unix.Close(socket)
	})
	defer cu.Clean()

	sa := &unix.SockaddrUnix{Name: path}
	if err := unix.Bind(socket, sa); err != nil {
		return nil, fmt.Errorf("bind(%q): %w", path, err)
	}
	if err := unix.Listen(socket, 5); err != nil {
		return nil, fmt.Errorf("listen(): %w", err)
	}

	server := &server{
		path:   path,
		fd:     fd.New(socket),
		stopCh: make(chan struct{}),
	}
	go server.run()
	cu.Release()
	return server, nil
}

func (s *server) run() {
	defer func() {
		s.stopCh <- struct{}{}
	}()
	for {
		client, _, err := unix.Accept(s.fd.FD())
		if err != nil {
			panic(err)
		}
		go s.handleClient(client)
	}
}

func (s *server) handleClient(client int) {
	defer unix.Close(client)

	var buf = make([]byte, 1024*1024)
	for {
		read, err := unix.Read(client, buf)
		if err != nil {
			return
		}
		if read == 0 {
			return
		}
		if read <= headerStructSize {
			panic("invalid message")
		}
		hdr := Header{}
		hdr.UnmarshalUnsafe(buf[0:headerStructSize])
		msg := &anypb.Any{}
		if err := proto.Unmarshal(buf[hdr.HeaderSize:read], msg); err != nil {
			panic("invalid proto")
		}
		s.mu.Lock()
		s.points = append(s.points, msg)
		s.mu.Unlock()
	}
}

func (s *server) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.points)
}

func (s *server) getPoints() []*anypb.Any {
	s.mu.Lock()
	defer s.mu.Unlock()
	cpy := make([]*anypb.Any, len(s.points))
	copy(cpy, s.points)
	return cpy
}

func (s *server) wait() {
	<-s.stopCh
}

func (s *server) close() {
	_ = s.fd.Close()
	_ = os.Remove(s.path)
}

func TestBasic(t *testing.T) {
	server, err := newServer()
	if err != nil {
		t.Fatalf("newServer(): %v", err)
	}
	defer server.close()

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

	r, err := New(nil, endpointFD)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	info := &pb.ExitNotifyParentInfo{ExitStatus: 123}
	if err := r.ExitNotifyParent(nil, seccheck.FieldSet{}, info); err != nil {
		t.Fatalf("ExitNotifyParent: %v", err)
	}

	testutil.Poll(func() error {
		if server.count() == 0 {
			return fmt.Errorf("waiting for points to arrive")
		}
		return nil
	}, 5*time.Second)
	if want, got := 1, server.count(); want != got {
		t.Errorf("wrong number of points, want: %d, got: %d", want, got)
	}
	any := server.getPoints()[0]

	got := &pb.ExitNotifyParentInfo{}
	if err := any.UnmarshalTo(got); err != nil {
		t.Errorf("any.UnmarshallTo(ExitNotifyParentInfo): %v", err)
	}
	if !proto.Equal(info, got) {
		t.Errorf("Received point is different, want: %+v, got: %+v", info, got)
	}
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

	r, err := New(nil, endpointFD)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	info := pb.ExitNotifyParentInfo{ExitStatus: 123}
	if err := r.ExitNotifyParent(nil, seccheck.FieldSet{}, &info); err != nil {
		t.Fatalf("ExitNotifyParent: %v", err)
	}
	check := func() error {
		got := server.out.String()
		match, _ := regexp.MatchString("gvisor.sentry.ExitNotifyParentInfo => exit_status: [ \t]*123", got)
		if !match {
			return fmt.Errorf("ExitNotifyParentInfo point didn't get to the server, out: %q", got)
		}
		return nil
	}
	if err := testutil.Poll(check, time.Second); err != nil {
		t.Errorf(err.Error())
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

	r, err := New(nil, endpointFD)
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
