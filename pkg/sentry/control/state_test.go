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

package control

import (
	"bytes"
	"io/fs"
	"os"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sentry/state/stateipc"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
)

type mockAsyncFileServer struct {
	mu        sync.Mutex
	files     map[string]*bytes.Buffer
	openCount map[string]int
}

func newMockAsyncFileServer() *mockAsyncFileServer {
	return &mockAsyncFileServer{
		files:     make(map[string]*bytes.Buffer),
		openCount: make(map[string]int),
	}
}

func (s *mockAsyncFileServer) Destroy() {}

func (s *mockAsyncFileServer) OpenRead(path string) (stateio.AsyncReader, error) {
	return nil, fs.ErrNotExist
}

func (s *mockAsyncFileServer) OpenWrite(path string) (stateio.AsyncWriter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.openCount[path]++
	buf, ok := s.files[path]
	if !ok {
		buf = new(bytes.Buffer)
		s.files[path] = buf
	}
	return stateio.NewIOWriter(buf, 1<<20 /* maxWriteBytes */, 1 /* maxRanges */, 1 /* maxParallel */), nil
}

func TestSetSaveOptsForCheckpointGoferWithSplitFS(t *testing.T) {
	mockServer := newMockAsyncFileServer()
	afs, err := stateipc.NewAsyncFileServer(mockServer)
	if err != nil {
		t.Fatalf("failed to create stateipc server: %v", err)
	}

	serverSocket, clientSocket, err := unet.SocketPair(false /* packet */)
	if err != nil {
		t.Fatalf("failed to create socket pair: %v", err)
	}
	defer serverSocket.Close()
	defer clientSocket.Close()

	rpcServer := urpc.NewServer()
	rpcServer.Register(afs)
	go rpcServer.Handle(serverSocket)

	clientFD, err := clientSocket.Release()
	if err != nil {
		t.Fatalf("failed to release client socket FD: %v", err)
	}
	clientFile := os.NewFile(uintptr(clientFD), "checkpointgofer-sock")

	resID := checkpoint.ResourceID{ContainerName: "cont1", Path: "/tmp"}
	opts := SaveOpts{
		UseCheckpointGofer:     true,
		HavePagesFile:          true,
		RunscVersion:           "test-version",
		SplitFSCheckpointPaths: []checkpoint.ResourceID{resID},
	}
	opts.FilePayload.Files = []*os.File{clientFile}

	saveOpts, err := ConvertToStateSaveOpts(&opts)
	if err != nil {
		t.Fatalf("ConvertToStateSaveOpts failed: %v", err)
	}

	if saveOpts.Destination == nil {
		t.Errorf("saveOpts.Destination is nil")
	}
	if saveOpts.PagesMetadata == nil {
		t.Errorf("saveOpts.PagesMetadata is nil")
	}
	if saveOpts.PagesFile == nil {
		t.Errorf("saveOpts.PagesFile is nil")
	}

	if saveOpts.FSSaveOpts == nil {
		t.Fatalf("saveOpts.FSSaveOpts is nil")
	}
	if saveOpts.FSSaveOpts.RunscVersion != "test-version" {
		t.Errorf("got RunscVersion %q, want %q", saveOpts.FSSaveOpts.RunscVersion, "test-version")
	}
	if len(saveOpts.FSSaveOpts.Paths) != 1 || saveOpts.FSSaveOpts.Paths[0] != resID {
		t.Errorf("got Paths %v, want [%v]", saveOpts.FSSaveOpts.Paths, resID)
	}
	if saveOpts.FSSaveOpts.ManifestFile == nil {
		t.Errorf("saveOpts.FSSaveOpts.ManifestFile is nil")
	}
	if saveOpts.FSSaveOpts.MultiTarFile == nil {
		t.Errorf("saveOpts.FSSaveOpts.MultiTarFile is nil")
	}
	if saveOpts.FSSaveOpts.PagesMetadataFile == nil {
		t.Errorf("saveOpts.FSSaveOpts.PagesMetadataFile is nil")
	}
	if saveOpts.FSSaveOpts.PagesFile == nil {
		t.Errorf("saveOpts.FSSaveOpts.PagesFile is nil")
	}

	// Write distinct test data to verify writing to distinct Sentry and Split-FS streams.
	if _, err := saveOpts.Destination.Write([]byte("sentry-state")); err != nil {
		t.Errorf("writing to Destination failed: %v", err)
	}
	if _, err := saveOpts.PagesMetadata.Write([]byte("sentry-pages-meta")); err != nil {
		t.Errorf("writing to PagesMetadata failed: %v", err)
	}
	if _, err := saveOpts.FSSaveOpts.ManifestFile.Write([]byte("fs-manifest")); err != nil {
		t.Errorf("writing to ManifestFile failed: %v", err)
	}
	if _, err := saveOpts.FSSaveOpts.MultiTarFile.Write([]byte("fs-multitar")); err != nil {
		t.Errorf("writing to MultiTarFile failed: %v", err)
	}
	if _, err := saveOpts.FSSaveOpts.PagesMetadataFile.Write([]byte("split-fs-pages-meta")); err != nil {
		t.Errorf("writing to PagesMetadataFile failed: %v", err)
	}

	// Close saveOpts to flush all buffered writers.
	saveOpts.Close()

	mockServer.mu.Lock()
	defer mockServer.mu.Unlock()
	expectedFiles := []string{
		checkpointfiles.StateFileName,
		checkpointfiles.PagesMetadataFileName,
		checkpointfiles.PagesFileName,
		checkpointfiles.FSCheckpointManifestPath,
		checkpointfiles.FSCheckpointMultiTarPath,
		checkpointfiles.FSCheckpointPagesMetadataPath,
		checkpointfiles.FSCheckpointPagesPath,
	}
	if len(mockServer.files) != len(expectedFiles) {
		t.Errorf("got %d files opened, want %d", len(mockServer.files), len(expectedFiles))
	}
	for _, f := range expectedFiles {
		if count := mockServer.openCount[f]; count != 1 {
			t.Errorf("expected file %q to be opened exactly once, got %d", f, count)
		}
	}

	// Verify distinct contents between Sentry and Split-FS streams.
	if got := mockServer.files[checkpointfiles.PagesMetadataFileName].String(); got != "sentry-pages-meta" {
		t.Errorf("got sentry pages metadata %q, want %q", got, "sentry-pages-meta")
	}
	if got := mockServer.files[checkpointfiles.FSCheckpointPagesMetadataPath].String(); got != "split-fs-pages-meta" {
		t.Errorf("got split-fs pages metadata %q, want %q", got, "split-fs-pages-meta")
	}
}

func TestSetSaveOptsForCheckpointGoferWithoutSplitFS(t *testing.T) {
	mockServer := newMockAsyncFileServer()
	afs, err := stateipc.NewAsyncFileServer(mockServer)
	if err != nil {
		t.Fatalf("failed to create stateipc server: %v", err)
	}

	serverSocket, clientSocket, err := unet.SocketPair(false /* packet */)
	if err != nil {
		t.Fatalf("failed to create socket pair: %v", err)
	}
	defer serverSocket.Close()
	defer clientSocket.Close()

	rpcServer := urpc.NewServer()
	rpcServer.Register(afs)
	go rpcServer.Handle(serverSocket)

	clientFD := clientSocket.FD()
	clientFile := os.NewFile(uintptr(clientFD), "checkpointgofer-sock")

	opts := SaveOpts{
		UseCheckpointGofer: true,
		HavePagesFile:      false,
		RunscVersion:       "test-version",
	}
	opts.FilePayload.Files = []*os.File{clientFile}

	saveOpts, err := ConvertToStateSaveOpts(&opts)
	if err != nil {
		t.Fatalf("ConvertToStateSaveOpts failed: %v", err)
	}
	defer saveOpts.Close()

	if saveOpts.Destination == nil {
		t.Errorf("saveOpts.Destination is nil")
	}
	if saveOpts.FSSaveOpts != nil {
		t.Errorf("saveOpts.FSSaveOpts is not nil")
	}
}
