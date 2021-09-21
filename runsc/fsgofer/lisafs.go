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

package fsgofer

import (
	"gvisor.dev/gvisor/pkg/lisafs"
)

// LisafsServer implements lisafs.ServerImpl for fsgofer.
type LisafsServer struct {
	lisafs.Server
	config Config
}

var _ lisafs.ServerImpl = (*LisafsServer)(nil)

// NewLisafsServer initializes a new lisafs server for fsgofer.
func NewLisafsServer(config Config) *LisafsServer {
	s := &LisafsServer{config: config}
	s.Server.Init(s)
	return s
}

// Mount implements lisafs.ServerImpl.Mount.
func (s *LisafsServer) Mount(c *lisafs.Connection, mountPath string) (lisafs.ControlFDImpl, lisafs.Inode, error) {
	panic("unimplemented")
}

// MaxMessageSize implements lisafs.ServerImpl.MaxMessageSize.
func (s *LisafsServer) MaxMessageSize() uint32 {
	return lisafs.MaxMessageSize()
}

// SupportedMessages implements lisafs.ServerImpl.SupportedMessages.
func (s *LisafsServer) SupportedMessages() []lisafs.MID {
	return []lisafs.MID{
		lisafs.Mount,
		lisafs.Channel,
	}
}
