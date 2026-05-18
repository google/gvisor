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

	// renameMu synchronizes rename operations within this filesystem tree.
	renameMu sync.RWMutex

	// handlers is a list of RPC handlers which can be indexed by the handler's
	// corresponding MID.
	handlers []RPCHandler

	// root is the root of the filesystem tree being managed by this server.
	// root is immutable. Server holds a ref on root for its entire lifetime.
	root *Node
}

// ConnectionOpts defines connection-specific behavior.
type ConnectionOpts struct {
	// Readonly indicates if this connection is readonly. All write operations
	// will fail with EROFS.
	Readonly bool

	// WalkStatSupported is set to true if it's safe to call
	// ControlFDImpl.WalkStat and let the file implementation perform the walk
	// without holding locks on any of the descendant's Nodes.
	WalkStatSupported bool

	// SetAttrOnDeleted is set to true if it's safe to call ControlFDImpl.SetStat
	// for deleted files.
	SetAttrOnDeleted bool

	// AllocateOnDeleted is set to true if it's safe to call OpenFDImpl.Allocate
	// for deleted files.
	AllocateOnDeleted bool

	// OpenOnDeleted is set to true if it's safe to call ControlFDImpl.Open for
	// deleted files.
	OpenOnDeleted bool
}

// NewServer creates a new Server.
func NewServer() *Server {
	var s Server
	s.handlers = handlers[:]
	s.root = &Node{}
	// s owns the ref on s.root.
	s.root.InitLocked("", nil)
	return &s
}

// SetHandlers overrides the server's RPC handlers. Mainly should only be used
// for tests.
func (s *Server) SetHandlers(handlers []RPCHandler) {
	s.handlers = handlers
}

// withRenameReadLock invokes fn with the server's rename mutex locked for
// reading. This ensures that no rename operations occur concurrently.
func (s *Server) withRenameReadLock(fn func() error) error {
	s.renameMu.RLock()
	defer s.renameMu.RUnlock()
	return fn()
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

// Destroy releases resources being used by this server.
func (s *Server) Destroy() {
	s.root.DecRef(nil)
}

// ConnectionImpl contains the implementation details for a Connection.
type ConnectionImpl interface {
	// Mount is called when a Mount RPC is made. It mounts the connection on
	// mountNode. Mount may optionally donate a host FD to the mount point.
	//
	// Mount has a read concurrency guarantee on mountNode.
	Mount(c *Connection, mountNode *Node) (*ControlFD, Statx, int, error)

	// SupportedMessages returns a list of messages that the connection
	// implementation supports.
	SupportedMessages() []MID

	// MaxMessageSize is the maximum payload length (in bytes) that can be sent
	// to this connection implementation.
	MaxMessageSize() uint32
}
