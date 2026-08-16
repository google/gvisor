// Copyright 2026 The gVisor Authors.
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

// Package scsdk provides an SDK library for seccheck consumers to interact
// with running sandboxes via RPC and consume security events.
package scsdk

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	controlclient "gvisor.dev/gvisor/pkg/control/client"
	"gvisor.dev/gvisor/pkg/urpc"
)

// SandboxClient is a client for communicating with a running gVisor sandbox via its
// Unix-domain control socket.
type SandboxClient struct {
	urpc *urpc.Client
}

// Connect creates a new SandboxClient connected to the sandbox control socket at
// socketPath (e.g. "/var/run/runsc/<id>/control").
func Connect(socketPath string) (*SandboxClient, error) {
	conn, err := connectToSocket(socketPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to control socket %q: %w", socketPath, err)
	}
	return &SandboxClient{urpc: conn}, nil
}

// NewSandboxClient creates a new SandboxClient wrapping an existing *urpc.Client.
func NewSandboxClient(conn *urpc.Client) (*SandboxClient, error) {
	if conn == nil {
		return nil, fmt.Errorf("urpc client is required")
	}
	return &SandboxClient{urpc: conn}, nil
}

// Close closes the underlying control socket connection.
func (c *SandboxClient) Close() error {
	if c.urpc == nil {
		return nil
	}
	return c.urpc.Close()
}

func connectToSocket(path string) (*urpc.Client, error) {
	if len(path) >= linux.UnixPathMax {
		sockFD, err := unix.Open(path, unix.O_PATH, 0)
		if err != nil {
			return nil, fmt.Errorf("opening socket at %q: %w", path, err)
		}
		defer unix.Close(sockFD)
		path = filepath.Join("/proc/self/fd", fmt.Sprintf("%d", sockFD))
	}
	return controlclient.ConnectTo(path)
}
