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

// Package server provides a common server implementation that can connect with
// remote.Remote.
package server

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

// ClientHandler is used to interface with client that connect to the server.
type ClientHandler interface {
	// NewClient is called when a new client connects to the server. It returns
	// a handler that will be bound to the client.
	NewClient() (MessageHandler, error)
}

// MessageHandler is used to process messages from a client.
type MessageHandler interface {
	// Message processes a single message. raw contains the entire unparsed
	// message. hdr is the parser message header and payload is the unparsed
	// message data.
	Message(raw []byte, hdr wire.Header, payload []byte) error

	// Version returns what wire version of the protocol is supported.
	Version() uint32

	// Close closes the handler.
	Close()
}

type client struct {
	socket  *unet.Socket
	handler MessageHandler
}

func (c client) close() {
	_ = c.socket.Close()
	c.handler.Close()
}

// CommonServer provides common functionality to connect and process messages
// from different clients. Implementors decide how clients and messages are
// handled, e.g. counting messages for testing.
type CommonServer struct {
	// Endpoint is the path to the socket that the server listens to.
	Endpoint string

	socket *unet.ServerSocket

	handler ClientHandler

	cond sync.Cond

	// +checklocks:cond.L
	clients []client
}

// Init initializes the server. It must be called before it is used.
func (s *CommonServer) Init(path string, handler ClientHandler) {
	s.Endpoint = path
	s.handler = handler
	s.cond = sync.Cond{L: &sync.Mutex{}}
}

// Start creates the socket file and listens for new connections.
func (s *CommonServer) Start() error {
	socket, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return fmt.Errorf("socket(AF_UNIX, SOCK_SEQPACKET, 0): %w", err)
	}
	cu := cleanup.Make(func() {
		_ = unix.Close(socket)
	})
	defer cu.Clean()

	sa := &unix.SockaddrUnix{Name: s.Endpoint}
	if err := unix.Bind(socket, sa); err != nil {
		return fmt.Errorf("bind(%q): %w", s.Endpoint, err)
	}

	s.socket, err = unet.NewServerSocket(socket)
	if err != nil {
		return err
	}
	cu.Add(func() { s.socket.Close() })

	if err := s.socket.Listen(); err != nil {
		return err
	}

	go s.run()
	cu.Release()
	return nil
}

func (s *CommonServer) run() {
	for {
		socket, err := s.socket.Accept()
		if err != nil {
			// EBADF returns when the socket closes.
			if !errors.Is(err, unix.EBADF) {
				log.Warningf("socket.Accept(): %v", err)
			}
			return
		}
		msgHandler, err := s.handler.NewClient()
		if err != nil {
			log.Warningf("handler.NewClient: %v", err)
			return
		}
		client := client{
			socket:  socket,
			handler: msgHandler,
		}
		s.cond.L.Lock()
		s.clients = append(s.clients, client)
		s.cond.Broadcast()
		s.cond.L.Unlock()

		if err := s.handshake(client); err != nil {
			log.Warningf(err.Error())
			s.closeClient(client)
			continue
		}
		go s.handleClient(client)
	}
}

// handshake performs version exchange with client. See common.proto for details
// about the protocol.
func (s *CommonServer) handshake(client client) error {
	var in [1024]byte
	read, err := client.socket.Read(in[:])
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

	hsOut := pb.Handshake{Version: client.handler.Version()}
	out, err := proto.Marshal(&hsOut)
	if err != nil {
		return fmt.Errorf("marshalling handshake message: %w", err)
	}
	if _, err := client.socket.Write(out); err != nil {
		return fmt.Errorf("sending handshake message: %w", err)
	}
	return nil
}

func (s *CommonServer) handleClient(client client) {
	defer s.closeClient(client)

	var buf = make([]byte, 1024*1024)
	for {
		read, err := client.socket.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, unix.EBADF) {
				// Both errors indicate that the socket has been closed.
				return
			}
			panic(err)
		}
		if read < wire.HeaderStructSize {
			panic("message too small")
		}
		hdr := wire.Header{}
		hdr.UnmarshalUnsafe(buf[0:wire.HeaderStructSize])
		if read < int(hdr.HeaderSize) {
			panic(fmt.Sprintf("message truncated, header size: %d, read: %d", hdr.HeaderSize, read))
		}
		if err := client.handler.Message(buf[:read], hdr, buf[hdr.HeaderSize:read]); err != nil {
			panic(err)
		}
	}
}

func (s *CommonServer) closeClient(client client) {
	client.close()

	// Stop tracking this client.
	s.cond.L.Lock()
	for i, c := range s.clients {
		if c == client {
			s.clients = append(s.clients[:i], s.clients[i+1:]...)
			break
		}
	}
	s.cond.Broadcast()
	s.cond.L.Unlock()
}

// Close stops listening and closes all connections.
func (s *CommonServer) Close() {
	if s.socket != nil {
		_ = s.socket.Close()
	}
	s.cond.L.Lock()
	for _, client := range s.clients {
		client.close()
	}
	s.clients = nil
	s.cond.Broadcast()
	s.cond.L.Unlock()
	_ = os.Remove(s.Endpoint)
}

// WaitForNoClients waits until the number of clients connected reaches 0.
func (s *CommonServer) WaitForNoClients() {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	for len(s.clients) > 0 {
		s.cond.Wait()
	}
}
