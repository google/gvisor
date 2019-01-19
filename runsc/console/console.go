// Copyright 2018 Google LLC
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

// Package console contains utilities for working with pty consols in runsc.
package console

import (
	"fmt"
	"net"
	"os"

	"github.com/kr/pty"
	"golang.org/x/sys/unix"
)

// NewWithSocket creates pty master/slave pair, sends the master FD over the given
// socket, and returns the slave.
func NewWithSocket(socketPath string) (*os.File, error) {
	// Create a new pty master and slave.
	ptyMaster, ptySlave, err := pty.Open()
	if err != nil {
		return nil, fmt.Errorf("opening pty: %v", err)
	}
	defer ptyMaster.Close()

	// Get a connection to the socket path.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		ptySlave.Close()
		return nil, fmt.Errorf("dialing socket %q: %v", socketPath, err)
	}
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		ptySlave.Close()
		return nil, fmt.Errorf("connection is not a UnixConn: %T", conn)
	}
	socket, err := uc.File()
	if err != nil {
		ptySlave.Close()
		return nil, fmt.Errorf("getting file for unix socket %v: %v", uc, err)
	}
	defer socket.Close()

	// Send the master FD over the connection.
	msg := unix.UnixRights(int(ptyMaster.Fd()))
	if err := unix.Sendmsg(int(socket.Fd()), []byte("pty-master"), msg, nil, 0); err != nil {
		ptySlave.Close()
		return nil, fmt.Errorf("sending console over unix socket %q: %v", socketPath, err)
	}
	return ptySlave, nil
}
