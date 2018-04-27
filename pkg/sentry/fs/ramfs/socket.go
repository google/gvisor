// Copyright 2018 Google Inc.
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

package ramfs

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix"
)

// Socket represents a socket.
type Socket struct {
	Entry

	// ep is the bound endpoint.
	ep unix.BoundEndpoint
}

// InitSocket initializes a socket.
func (s *Socket) InitSocket(ctx context.Context, ep unix.BoundEndpoint, owner fs.FileOwner, perms fs.FilePermissions) {
	s.InitEntry(ctx, owner, perms)
	s.ep = ep
}

// BoundEndpoint returns the socket data.
func (s *Socket) BoundEndpoint(*fs.Inode, string) unix.BoundEndpoint {
	// ramfs only supports stored sentry internal sockets. Only gofer sockets
	// care about the path argument.
	return s.ep
}
