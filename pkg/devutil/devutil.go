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
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fsutil"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/unet"
)

// GoferClient is the lisafs client for the /dev gofer connection.
type GoferClient struct {
	clientFD lisafs.ClientFD
	hostFD   int
	contName string
}

// NewGoferClient establishes the LISAFS connection to the dev gofer server.
// It takes ownership of fd. contName is the owning container name.
func NewGoferClient(ctx context.Context, contName string, fd int) (*GoferClient, error) {
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
		contName: contName,
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

// ContainerName returns the name of the container that owns this gofer.
func (g *GoferClient) ContainerName() string {
	return g.contName
}

// DirentNames returns names of all the dirents for /dev on the gofer.
func (g *GoferClient) DirentNames(ctx context.Context) ([]string, error) {
	if g.hostFD >= 0 {
		return fsutil.DirentNames(g.hostFD)
	}
	client := g.clientFD.Client()
	openFDID, _, err := g.clientFD.OpenAt(ctx, unix.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("failed to open dev from gofer: %v", err)
	}
	defer client.CloseFD(ctx, openFDID, true /* flush */)
	openFD := client.NewFD(openFDID)
	const count = int32(64 * 1024)
	var names []string
	for {
		dirents, err := openFD.Getdents64(ctx, count)
		if err != nil {
			return nil, fmt.Errorf("Getdents64 RPC failed: %v", err)
		}
		if len(dirents) == 0 {
			break
		}
		for i := range dirents {
			names = append(names, string(dirents[i].Name))
		}
	}
	return names, nil
}

// OpenAt opens the device file at /dev/{name} on the gofer.
func (g *GoferClient) OpenAt(ctx context.Context, name string, flags uint32) (int, error) {
	flags &= unix.O_ACCMODE
	if g.hostFD >= 0 {
		return unix.Openat(g.hostFD, name, int(flags|unix.O_NOFOLLOW), 0)
	}
	childInode, err := g.clientFD.Walk(ctx, name)
	if err != nil {
		log.Infof("failed to walk %q from dev gofer FD", name)
		return 0, err
	}
	client := g.clientFD.Client()
	childFD := client.NewFD(childInode.ControlFD)

	childOpenFD, childHostFD, err := childFD.OpenAt(ctx, flags)
	if err != nil {
		log.Infof("failed to open %q from child FD", name)
		client.CloseFD(ctx, childFD.ID(), true /* flush */)
		return 0, err
	}
	client.CloseFD(ctx, childFD.ID(), false /* flush */)
	client.CloseFD(ctx, childOpenFD, true /* flush */)
	return childHostFD, nil
}

// GoferClientProvider provides a GoferClient for a given container.
type GoferClientProvider interface {
	GetDevGoferClient(contName string) *GoferClient
}
