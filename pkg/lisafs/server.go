// Copyright 2021 The gVisor Authors.
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

package lisafs

import (
	"gvisor.dev/gvisor/pkg/sync"
)

// Server serves a filesystem tree. Multiple connections on different mount
// points can be started on a server. The server provides utilities to safely
// modify the filesystem tree across its connections (mount points). Note that
// it does not support synchronizing filesystem tree mutations across other
// servers serving the same filesystem subtree. Server also manages the
// lifecycle of all connections.
type Server struct {
	// connWg counts the number of active connections being tracked.
	connWg sync.WaitGroup

	// RenameMu synchronizes rename operations within this filesystem tree.
	RenameMu sync.RWMutex

	// handlers is a list of RPC handlers which can be indexed by the handler's
	// corresponding MID.
	handlers []RPCHandler

	// mountPoints keeps track of all the mount points this server serves.
	mpMu        sync.RWMutex
	mountPoints []*ControlFD

	// impl is the server implementation which embeds this server.
	impl ServerImpl
}

// Init must be called before first use of server.
func (s *Server) Init(impl ServerImpl) {
	s.impl = impl
	s.handlers = handlers[:]
}

// InitTestOnly is the same as Init except that it allows to swap out the
// underlying handlers with something custom. This is for test only.
func (s *Server) InitTestOnly(impl ServerImpl, handlers []RPCHandler) {
	s.impl = impl
	s.handlers = handlers
}

// WithRenameReadLock invokes fn with the server's rename mutex locked for
// reading. This ensures that no rename operations occur concurrently.
func (s *Server) WithRenameReadLock(fn func() error) error {
	s.RenameMu.RLock()
	err := fn()
	s.RenameMu.RUnlock()
	return err
}

// StartConnection starts the connection on a separate goroutine and tracks it.
func (s *Server) StartConnection(c *Connection) {
	s.connWg.Add(1)
	go func() {
		c.Run()
		s.connWg.Done()
	}()
}

// Wait waits for all connections started via StartConnection() to terminate.
func (s *Server) Wait() {
	s.connWg.Wait()
}

func (s *Server) addMountPoint(root *ControlFD) {
	s.mpMu.Lock()
	defer s.mpMu.Unlock()
	s.mountPoints = append(s.mountPoints, root)
}

func (s *Server) forEachMountPoint(fn func(root *ControlFD)) {
	s.mpMu.RLock()
	defer s.mpMu.RUnlock()
	for _, mp := range s.mountPoints {
		fn(mp)
	}
}

// ServerImpl contains the implementation details for a Server.
// Implementations of ServerImpl should contain their associated Server by
// value as their first field.
type ServerImpl interface {
	// Mount is called when a Mount RPC is made. It mounts the connection at
	// mountPath.
	//
	// Precondition: mountPath == path.Clean(mountPath).
	Mount(c *Connection, mountPath string) (ControlFDImpl, Inode, error)

	// SupportedMessages returns a list of messages that the server
	// implementation supports.
	SupportedMessages() []MID

	// MaxMessageSize is the maximum payload length (in bytes) that can be sent
	// to this server implementation.
	MaxMessageSize() uint32
}
