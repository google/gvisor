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

// Package test provides functionality used to test the remote sink.
package test

import (
	"io/ioutil"
	"os"
	"path/filepath"

	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/server"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"
	"gvisor.dev/gvisor/pkg/sync"
)

// Server is the counterpart to the sinks.Remote. It receives connections
// remote sink and stores all points that it receives.
type Server struct {
	server.CommonServer

	cond sync.Cond

	// +checklocks:cond.L
	points []Message

	mu sync.Mutex

	// +checklocks:mu
	version uint32
}

// Message corresponds to a single message sent from sinks.Remote.
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
	s := &Server{
		version: wire.CurrentVersion,
		cond:    sync.Cond{L: &sync.Mutex{}},
	}
	s.CommonServer.Init(filepath.Join(dir, "remote.sock"), s)
	if err := s.CommonServer.Start(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return s, nil
}

// NewClient returns a new MessageHandler to process messages.
func (s *Server) NewClient() (server.MessageHandler, error) {
	return &msgHandler{owner: s}, nil
}

// Count return the number of points it has received.
func (s *Server) Count() int {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	return len(s.points)
}

// Reset throws aways all points received so far and returns the number of
// points discarded.
func (s *Server) Reset() int {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	count := len(s.points)
	s.points = nil
	return count
}

// GetPoints returns all points that it has received.
func (s *Server) GetPoints() []Message {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	cpy := make([]Message, len(s.points))
	copy(cpy, s.points)
	return cpy
}

// WaitForCount waits for the number of points to reach the desired number.
func (s *Server) WaitForCount(count int) {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	for len(s.points) < count {
		s.cond.Wait()
	}
	return
}

// SetVersion sets the version to be used in handshake.
func (s *Server) SetVersion(newVersion uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.version = newVersion
}

type msgHandler struct {
	owner *Server
}

// Message stores the message type and payload.
func (m *msgHandler) Message(_ []byte, hdr wire.Header, payload []byte) error {
	msg := Message{
		MsgType: pb.MessageType(hdr.MessageType),
		Msg:     make([]byte, len(payload)),
	}
	copy(msg.Msg, payload)

	m.owner.cond.L.Lock()
	defer m.owner.cond.L.Unlock()
	m.owner.points = append(m.owner.points, msg)
	m.owner.cond.Broadcast()
	return nil
}

// Version returns the wire version supported or overriden by SetVersion.
func (m *msgHandler) Version() uint32 {
	m.owner.mu.Lock()
	defer m.owner.mu.Unlock()
	return m.owner.version
}

// Close implements server.MessageHandler.
func (m *msgHandler) Close() {}
