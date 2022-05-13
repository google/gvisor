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

// Package test provides functionality used to test the remote checker.
package test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/checkers/remote/wire"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/pkg/unet"
)

// Server is the counterpart to the checkers.Remote. It receives connections
// remote checkers and stores all points that it receives.
type Server struct {
	Path   string
	socket *unet.ServerSocket

	mu sync.Mutex

	// +checklocks:mu
	clients []*unet.Socket

	// +checklocks:mu
	points []Message

	version uint32
}

// Message corresponds to a single message sent from checkers.Remote.
type Message struct {
	// MsgType indicates what is the type of Msg.
	MsgType pb.MessageType
	// Msg is the payload to the message that can be decoded using MsgType.
	Msg []byte
}

// NewServer creates a new server that listens to a UDS that it creates under
// os.TempDir.
func NewServer() (*Server, error) {
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

func newServerPath(path string) (*Server, error) {
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

	ss, err := unet.NewServerSocket(socket)
	if err != nil {
		return nil, err
	}
	cu.Add(func() { ss.Close() })

	if err := ss.Listen(); err != nil {
		return nil, err
	}

	server := &Server{
		Path:    path,
		socket:  ss,
		version: wire.CurrentVersion,
	}
	go server.run()
	cu.Release()
	return server, nil
}

func (s *Server) run() {
	for {
		client, err := s.socket.Accept()
		if err != nil {
			// EBADF returns when the socket closes.
			if !errors.Is(err, unix.EBADF) {
				log.Warningf("socket.Accept(): %v", err)
			}
			return
		}
		if err := s.handshake(client); err != nil {
			log.Warningf(err.Error())
			_ = client.Close()
			continue
		}
		s.mu.Lock()
		s.clients = append(s.clients, client)
		s.mu.Unlock()
		go s.handleClient(client)
	}
}

// handshake performs version exchange with client. See common.proto for details
// about the protocol.
func (s *Server) handshake(client *unet.Socket) error {
	var in [1024]byte
	read, err := client.Read(in[:])
	if err != nil {
		return fmt.Errorf("reading handshake message: %w", err)
	}
	hsIn := pb.Handshake{}
	if err := proto.Unmarshal(in[:read], &hsIn); err != nil {
		return fmt.Errorf("unmarshalling handshake message: %w", err)
	}
	if hsIn.Version != wire.CurrentVersion {
		return fmt.Errorf("wrong version number, want: %d, got, %d", wire.CurrentVersion, hsIn.Version)
	}

	hsOut := pb.Handshake{Version: s.version}
	out, err := proto.Marshal(&hsOut)
	if err != nil {
		return fmt.Errorf("marshalling handshake message: %w", err)
	}
	if _, err := client.Write(out); err != nil {
		return fmt.Errorf("sending handshake message: %w", err)
	}
	return nil
}

func (s *Server) handleClient(client *unet.Socket) {
	defer func() {
		s.mu.Lock()
		for i, c := range s.clients {
			if c == client {
				s.clients = append(s.clients[:i], s.clients[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
		_ = client.Close()
	}()

	var buf = make([]byte, 1024*1024)
	for {
		read, err := client.Read(buf)
		if err != nil {
			return
		}
		if read == 0 {
			return
		}
		if read < wire.HeaderStructSize {
			panic("invalid message")
		}
		hdr := wire.Header{}
		hdr.UnmarshalUnsafe(buf[0:wire.HeaderStructSize])
		if read < int(hdr.HeaderSize) {
			panic(fmt.Sprintf("message truncated, header size: %d, readL %d", hdr.HeaderSize, read))
		}
		msg := Message{
			MsgType: pb.MessageType(hdr.MessageType),
			Msg:     buf[hdr.HeaderSize:read],
		}
		s.mu.Lock()
		s.points = append(s.points, msg)
		s.mu.Unlock()
	}
}

// Count return the number of points it has received.
func (s *Server) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.points)
}

// Reset throws aways all points received so far and returns the number of
// points discarded.
func (s *Server) Reset() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := len(s.points)
	s.points = nil
	return count
}

// GetPoints returns all points that it has received.
func (s *Server) GetPoints() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	cpy := make([]Message, len(s.points))
	copy(cpy, s.points)
	return cpy
}

// Close stops listenning and closes all connections.
func (s *Server) Close() {
	_ = s.socket.Close()
	s.mu.Lock()
	for _, client := range s.clients {
		_ = client.Close()
	}
	s.mu.Unlock()
	_ = os.Remove(s.Path)
}

// WaitForCount waits for the number of points to reach the desired number for
// 5 seconds. It fails if not received in time.
func (s *Server) WaitForCount(count int) error {
	return testutil.Poll(func() error {
		if got := s.Count(); got < count {
			return fmt.Errorf("waiting for points %d to arrive, received %d", count, got)
		}
		return nil
	}, 5*time.Second)
}

// SetVersion sets the version to be used in handshake.
func (s *Server) SetVersion(newVersion uint32) {
	s.version = newVersion
}
