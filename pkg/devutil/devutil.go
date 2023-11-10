// Copyright 2023 The gVisor Authors.
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

// Package devutil provides device specific utilities.
package devutil

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/unet"
)

// GoferClient is the lisafs client for the /dev gofer connection.
type GoferClient struct {
	clientFD lisafs.ClientFD
	hostFD   int
}

// NewGoferClient establishes the LISAFS connection to the dev gofer server.
// It takes ownership of fd.
func NewGoferClient(ctx context.Context, fd int) (*GoferClient, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	sock, err := unet.NewSocket(fd)
	if err != nil {
		ctx.Warningf("failed to create socket for dev gofer client: %v", err)
		return nil, err
	}
	client, devInode, devHostFD, err := lisafs.NewClient(sock)
	if err != nil {
		ctx.Warningf("failed to create dev gofer client: %v", err)
		return nil, err
	}
	return &GoferClient{
		clientFD: client.NewFD(devInode.ControlFD),
		hostFD:   devHostFD,
	}, nil
}

// Close closes the LISAFS connection.
func (g *GoferClient) Close() {
	// Close the connection to the server. This implicitly closes all FDs.
	g.clientFD.Client().Close()
	if g.hostFD >= 0 {
		_ = unix.Close(g.hostFD)
	}
}
