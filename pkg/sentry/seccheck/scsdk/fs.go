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

// This file provides functions and SandboxClient methods for reading file
// contents from a container (similar to 'runsc read') over the sandbox control
// socket.
//
// # Usage
//
// To read a file from a running container into memory using a SandboxClient:
//
//	c, err := scsdk.Connect("/var/run/runsc/<sandbox-id>/control")
//	if err != nil {
//		log.Fatalf("failed to connect: %v", err)
//	}
//	defer c.Close()
//
//	data, err := c.ReadFile(scsdk.ReadOptions{
//		ContainerID: "container-id", // leave empty for root container
//		Path:        "/etc/passwd",
//		Offset:      0,              // start at beginning of file
//		Size:        4096,           // 0 means unlimited
//	})
//	if err != nil {
//		log.Fatalf("failed to read file: %v", err)
//	}
//	fmt.Printf("File content: %s\n", data)
//
// To stream a file directly to an io.Writer or *os.File without buffering the
// entire contents in memory:
//
//	err := c.ReadFileToWriter(scsdk.ReadOptions{
//		Path: "/var/log/app.log",
//	}, os.Stdout)
//	if err != nil {
//		log.Fatalf("failed to stream file: %v", err)
//	}
//
// For quick one-shot reads without manually managing a SandboxClient, you can use ReadFile
// or ReadFileToWriter:
//
//	data, err := scsdk.ReadFile("/var/run/runsc/<sandbox-id>/control", scsdk.ReadOptions{
//		Path: "/proc/version",
//	})

package scsdk

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"

	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/urpc"
)

// ReadOptions specifies parameters for reading a file from a container.
type ReadOptions struct {
	// ContainerID identifies which container's filesystem to read from.
	// If empty, reads from the root container.
	ContainerID string

	// Path is the filesystem path for the file to read.
	Path string

	// Offset is the byte offset in the file to read from.
	Offset int64

	// Size is the maximum number of bytes to read (0 means unlimited).
	Size int64
}

// Options is an alias for ReadOptions for convenience.
type Options = ReadOptions

// ReadFile connects to the sandbox control socket at socketPath and reads the file
// specified by opts, returning its contents as a byte slice.
func ReadFile(socketPath string, opts ReadOptions) ([]byte, error) {
	c, err := Connect(socketPath)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.ReadFile(opts)
}

// ReadFileToWriter connects to the sandbox control socket at socketPath and reads
// the file specified by opts, streaming its contents into w.
func ReadFileToWriter(socketPath string, opts ReadOptions, w io.Writer) error {
	c, err := Connect(socketPath)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.ReadFileToWriter(opts, w)
}

// ReadFile reads the file specified by opts from the container filesystem,
// returning its contents as a byte slice.
func (c *SandboxClient) ReadFile(opts ReadOptions) ([]byte, error) {
	var buf bytes.Buffer
	if err := c.ReadFileToWriter(opts, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ReadFileToWriter reads the file specified by opts from the container
// filesystem and streams its contents into w.
func (c *SandboxClient) ReadFileToWriter(opts ReadOptions, w io.Writer) error {
	if c == nil || c.urpc == nil {
		return fmt.Errorf("client is not connected")
	}
	if w == nil {
		return fmt.Errorf("writer is required")
	}
	if opts.Path == "" {
		return fmt.Errorf("file path is required")
	}
	if opts.Offset < 0 || opts.Size < 0 {
		return fmt.Errorf("offset and size must be non-negative")
	}

	rpcOpts := control.ReadOpts{
		ContainerID: opts.ContainerID,
		Path:        opts.Path,
		Offset:      opts.Offset,
		Size:        opts.Size,
	}

	// If w is already an *os.File, pass its file descriptor directly to the server.
	if f, ok := w.(*os.File); ok {
		rpcOpts.FilePayload = urpc.FilePayload{Files: []*os.File{f}}
		return c.urpc.Call("Fs.Read", &rpcOpts, nil)
	}

	// Otherwise, use an os.Pipe to bridge the file descriptor from Fs.Read to io.Writer.
	r, pipeW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("creating pipe: %w", err)
	}
	defer r.Close()

	rpcOpts.FilePayload = urpc.FilePayload{Files: []*os.File{pipeW}}

	var callErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer pipeW.Close()
		callErr = c.urpc.Call("Fs.Read", &rpcOpts, nil)
	}()

	_, copyErr := io.Copy(w, r)
	wg.Wait()

	if callErr != nil {
		return callErr
	}
	return copyErr
}
