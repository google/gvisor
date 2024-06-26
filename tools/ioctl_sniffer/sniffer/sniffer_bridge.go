// Copyright 2024 The gVisor Authors.
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

package sniffer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/tools/ioctl_sniffer/ioctl_go_proto"
)

// Connection is a connection to the sniffer hook.
type Connection struct {
	protoBytesBuf []byte
	conn          net.Conn
}

// readFullWithContext tries to fill the buffer with data from the connection. It returns an error
// once the context is cancelled and the read would block, or if the read fails.
func (c *Connection) readFullWithContext(ctx context.Context, buf []byte) error {
	nread := 0
	for {
		// Don't block for long if we're cancelled.
		timeout := time.Second
		if ctx.Err() != nil {
			timeout = time.Millisecond
		}

		if err := c.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("failed to set deadline: %w", err)
		}

		n, err := c.conn.Read(buf[nread:])
		if err != nil {
			// Only retry if we're not cancelled.
			if errors.Is(err, os.ErrDeadlineExceeded) && ctx.Err() == nil {
				continue
			}
			return fmt.Errorf("failed to read from connection: %w", err)
		}
		nread += n
		if nread == len(buf) {
			break
		}
	}

	return nil
}

// ReadIoctlProto reads a single ioctl proto from this connection. Our format is:
//   - 8 byte little endian uint64 containing the size of the proto.
//   - The proto bytes.
//
// This should match the format in sniffer_bridge.h.
func (c *Connection) ReadIoctlProto(ctx context.Context) (*pb.Ioctl, error) {
	// First read in proto size
	var protoSizeBuf [8]byte
	if err := c.readFullWithContext(ctx, protoSizeBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to read proto size: %w", err)
	}
	protoSize := binary.LittleEndian.Uint64(protoSizeBuf[:])

	// See if we need to reallocate the buffer.
	if cap(c.protoBytesBuf) < int(protoSize) {
		c.protoBytesBuf = make([]byte, protoSize)
	} else {
		c.protoBytesBuf = c.protoBytesBuf[:protoSize]
	}

	// Read the proto data.
	if err := c.readFullWithContext(ctx, c.protoBytesBuf); err != nil {
		return nil, fmt.Errorf("failed to read proto data: %w", err)
	}

	// Unmarshal and parse proto.
	ioctl := &pb.Ioctl{}
	if err := proto.Unmarshal(c.protoBytesBuf, ioctl); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proto: %w", err)
	}

	return ioctl, nil
}

// Server is a server that accepts connections from the sniffer hook. It reads ioctl protos from
// each connection and sends them to the results channel.
type Server struct {
	resultsChan   chan *Results
	connectionsWG sync.WaitGroup
	listener      net.Listener
}

// NewServer creates a new Server.
func NewServer() *Server {
	return &Server{
		resultsChan: make(chan *Results),
	}
}

// Listen opens a new socket server.
func (s *Server) Listen() error {
	// Create a unique socket path for this process.
	// Go will automatically delete the file when the socket is closed.
	addr := fmt.Sprintf("/tmp/sniffer_bridge_%d.sock", os.Getpid())

	l, err := net.Listen("unix", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %w", err)
	}

	s.listener = l
	return nil
}

// Serve opens a new socket server, continually accepts connections from the socket and
// reads ioctl protos from each connection. It blocks until the context is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	// Accept connections from the socket and read ioctl protos from each connection.
	errChan := make(chan error)
	go func() {
		defer close(errChan)

		for ctx.Err() == nil {
			conn, err := s.listener.Accept()
			if err != nil {
				errChan <- fmt.Errorf("failed to accept connection: %w", err)
				return
			}

			s.connectionsWG.Add(1)
			go func() {
				conn := Connection{conn: conn}
				s.resultsChan <- conn.ReadHookOutput(ctx)
				s.connectionsWG.Done()
			}()
		}
	}()

	// Wait for the context cancellation.
	<-ctx.Done()
	if err := s.listener.Close(); err != nil {
		return fmt.Errorf("failed to close socket: %w", err)
	}
	for err := range errChan {
		if errors.Is(err, net.ErrClosed) {
			continue
		}
		return fmt.Errorf("failed to accept connection: %w", err)
	}
	return nil
}

// AllResults blocks until all connections have closed and returns an aggregate of all the results.
func (s *Server) AllResults() *Results {
	// Wait for all connections to close.
	// Do this in a separate goroutine so we can start reading from the results channel.
	go func() {
		s.connectionsWG.Wait()
		close(s.resultsChan)
	}()

	finalResults := NewResults()
	for results := range s.resultsChan {
		finalResults.Merge(results)
	}
	return finalResults
}

// Addr returns the address of the socket.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}
