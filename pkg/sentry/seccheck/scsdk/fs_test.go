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

package scsdk

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
)

type Fs struct {
	content []byte
	err     error
}

func (f *Fs) Read(o *control.ReadOpts, _ *struct{}) error {
	if f.err != nil {
		return f.err
	}
	if len(o.FilePayload.Files) != 1 {
		return fmt.Errorf("expected 1 file payload")
	}
	out := o.FilePayload.Files[0]
	defer out.Close()

	if o.Offset >= int64(len(f.content)) {
		return nil
	}
	data := f.content[o.Offset:]
	if o.Size > 0 && int64(len(data)) > o.Size {
		data = data[:o.Size]
	}
	_, err := out.Write(data)
	return err
}

func setupTestServer(t *testing.T, content []byte, srvErr error) (*SandboxClient, func()) {
	t.Helper()
	srv := urpc.NewServer()
	srv.Register(&Fs{content: content, err: srvErr})

	clientSock, serverSock, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("SocketPair failed: %v", err)
	}
	srv.StartHandling(serverSock)

	urpcClient := urpc.NewClient(clientSock)
	c, err := NewSandboxClient(urpcClient)
	if err != nil {
		t.Fatalf("NewSandboxClient failed: %v", err)
	}
	cleanup := func() {
		c.Close()
	}
	return c, cleanup
}

func TestReadFileFull(t *testing.T) {
	content := []byte("hello, seccheck world!")
	c, cleanup := setupTestServer(t, content, nil)
	defer cleanup()

	got, err := c.ReadFile(Options{Path: "/test/file"})
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("ReadFile got %q, want %q", string(got), string(content))
	}
}

func TestReadFileWithOffsetAndSize(t *testing.T) {
	content := []byte("hello, seccheck world!")
	c, cleanup := setupTestServer(t, content, nil)
	defer cleanup()

	got, err := c.ReadFile(Options{
		Path:   "/test/file",
		Offset: 7,
		Size:   8,
	})
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	want := []byte("seccheck")
	if !bytes.Equal(got, want) {
		t.Errorf("ReadFile got %q, want %q", string(got), string(want))
	}
}

func TestReadFileToWriter(t *testing.T) {
	content := []byte("streaming file content")
	c, cleanup := setupTestServer(t, content, nil)
	defer cleanup()

	var buf bytes.Buffer
	err := c.ReadFileToWriter(Options{Path: "/test/file"}, &buf)
	if err != nil {
		t.Fatalf("ReadFileToWriter failed: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), content) {
		t.Errorf("ReadFileToWriter got %q, want %q", buf.String(), string(content))
	}
}

func TestReadValidationErrors(t *testing.T) {
	c, cleanup := setupTestServer(t, nil, nil)
	defer cleanup()

	tests := []struct {
		name string
		opts Options
	}{
		{
			name: "empty path",
			opts: Options{Path: ""},
		},
		{
			name: "negative offset",
			opts: Options{Path: "/test", Offset: -1},
		},
		{
			name: "negative size",
			opts: Options{Path: "/test", Size: -5},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.ReadFile(tc.opts)
			if err == nil {
				t.Errorf("ReadFile expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestReadRPCError(t *testing.T) {
	wantErr := errors.New("file not found")
	c, cleanup := setupTestServer(t, nil, wantErr)
	defer cleanup()

	_, err := c.ReadFile(Options{Path: "/nonexistent"})
	if err == nil {
		t.Fatalf("ReadFile expected error, got nil")
	}
}

func TestReadSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "control.sock")

	srv := urpc.NewServer()
	srv.Register(&Fs{content: []byte("socket test content")})

	unixSock, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("unix.Socket: %v", err)
	}
	defer unix.Close(unixSock)

	addr := &unix.SockaddrUnix{Name: sockPath}
	if err := unix.Bind(unixSock, addr); err != nil {
		t.Fatalf("unix.Bind: %v", err)
	}
	if err := unix.Listen(unixSock, 5); err != nil {
		t.Fatalf("unix.Listen: %v", err)
	}

	serverSock, err := unet.NewServerSocket(unixSock)
	if err != nil {
		t.Fatalf("unet.NewServerSocket: %v", err)
	}
	defer serverSock.Close()

	go func() {
		for {
			conn, err := serverSock.Accept()
			if err != nil {
				return
			}
			srv.StartHandling(conn)
		}
	}()

	// Test one-shot convenience helper ReadFile.
	got, err := ReadFile(sockPath, Options{Path: "/test", Offset: 7, Size: 4})
	if err != nil {
		t.Fatalf("scsdk.ReadFile failed: %v", err)
	}
	if want := "test"; string(got) != want {
		t.Errorf("scsdk.ReadFile got %q, want %q", string(got), want)
	}

	// Test explicit SandboxClient connection and method invocation.
	c, err := Connect(sockPath)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer c.Close()
	got, err = c.ReadFile(Options{Path: "/test", Offset: 0, Size: 6})
	if err != nil {
		t.Fatalf("c.ReadFile failed: %v", err)
	}
	if want := "socket"; string(got) != want {
		t.Errorf("c.ReadFile got %q, want %q", string(got), want)
	}
}
