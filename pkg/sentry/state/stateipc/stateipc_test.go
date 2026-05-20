// Copyright 2025 The gVisor Authors.
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

package stateipc

import (
	"bytes"
	"io"
	"io/fs"
	"math/bits"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
)

// testParallel should be at least 32 so that a uint32 can be used as a bitset
// of in-use IDs.
const testParallel = 32

// testReadServer implements AsyncFileServerImpl by serving a single file from a
// byte slice.
type testReadServer struct {
	path         string
	data         []byte
	maxReadBytes uint64
}

// Destroy implements AsyncFileServerImpl.Destroy.
func (s *testReadServer) Destroy() {}

// OpenRead implements AsyncFileServerImpl.OpenRead.
func (s *testReadServer) OpenRead(path string) (stateio.AsyncReader, error) {
	if path == s.path {
		return stateio.NewIOReader(bytes.NewReader(s.data), s.maxReadBytes, 2 /* maxRanges */, testParallel), nil
	}
	return nil, fs.ErrNotExist
}

// OpenWrite implements AsyncFileServerImpl.OpenWrite.
func (s *testReadServer) OpenWrite(path string) (stateio.AsyncWriter, error) {
	panic("unexpected call to OpenWrite")
}

// testWriteServer implements AsyncFileServerImpl by writing a single file to a
// bytes.Buffer.
type testWriteServer struct {
	path          string
	buf           bytes.Buffer
	maxWriteBytes uint64
}

// Destroy implements AsyncFileServerImpl.Destroy.
func (s *testWriteServer) Destroy() {}

// OpenRead implements AsyncFileServerImpl.OpenRead.
func (s *testWriteServer) OpenRead(path string) (stateio.AsyncReader, error) {
	panic("unexpected call to OpenRead")
}

// OpenWrite implements AsyncFileServerImpl.OpenWrite.
func (s *testWriteServer) OpenWrite(path string) (stateio.AsyncWriter, error) {
	if path == s.path {
		return stateio.NewIOWriter(&s.buf, s.maxWriteBytes, 2 /* maxRanges */, testParallel), nil
	}
	return nil, fs.ErrNotExist
}

func TestRead(t *testing.T) {
	// Create random data.
	const testPath = "testfile"
	const chunkSize = 4096
	const dataLen = 1024 * chunkSize
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)

	// Create the destination file.
	memfd, buf, err := stateio.CreateMappedMemoryFD("stateipc.TestRead", dataLen)
	if err != nil {
		t.Fatalf("failed to create destination file: %v", err)
	}
	defer unix.Close(int(memfd))
	defer unix.Munmap(buf)

	// Set up the server and client.
	usrv := urpc.NewServer()
	server, err := NewAsyncFileServer(&testReadServer{
		path:         testPath,
		data:         data,
		maxReadBytes: chunkSize,
	})
	if err != nil {
		t.Fatalf("failed to create AsyncFileServer: %v", err)
	}
	usrv.Register(server)
	clientSock, serverSock, err := unet.SocketPair(false /* packet */)
	if err != nil {
		t.Fatalf("failed to create socketpair: %v", err)
	}
	client, err := NewAsyncFileClient(urpc.NewClient(clientSock))
	if err != nil {
		t.Fatalf("failed to create AsyncFileClient: %v", err)
	}
	defer client.DecRef()
	usrv.StartHandling(serverSock)

	// Open the file containing random data.
	ar, err := client.OpenRead(testPath)
	if err != nil {
		t.Fatalf("failed to open remote file: %v", err)
	}
	defer ar.Close()

	// Read the file using async reads.
	df, err := ar.RegisterDestinationFD(memfd, uint64(dataLen), nil)
	if err != nil {
		t.Fatalf("failed to register destination file: %v", err)
	}
	ids := uint32(0)
	off := 0
	done := 0
	var cs []stateio.Completion
	for done < dataLen {
		for ids != ^uint32(0) && off < dataLen {
			id := bits.TrailingZeros32(^ids)
			ids |= uint32(1) << id
			ar.AddRead(id, int64(off), df, memmap.FileRange{uint64(off), uint64(off) + chunkSize}, buf[off:off+chunkSize])
			off += chunkSize
		}
		cs, err := ar.Wait(cs[:0], 1 /* minCompletions */)
		if err != nil {
			t.Fatalf("AsyncReader.Wait failed: %v", err)
		}
		for _, c := range cs {
			if c.Err != nil && c.Err != io.EOF {
				t.Fatalf("AsyncReader returned completion with error: %v", c.Err)
			}
			if c.N != chunkSize {
				t.Fatalf("AsyncReader returned completion of %d bytes, want %d", c.N, chunkSize)
			}
			ids &^= uint32(1) << c.ID
			done += chunkSize
		}
	}

	if !bytes.Equal(data, buf) {
		t.Errorf("bytes differ")
	}
}

func TestReadv(t *testing.T) {
	// Create random data.
	const testPath = "testfile"
	const chunkSize = 4096
	const dataLen = 1024 * chunkSize
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)

	// Create the destination file.
	memfd, buf, err := stateio.CreateMappedMemoryFD("stateipc.TestReadv", dataLen)
	if err != nil {
		t.Fatalf("failed to create destination file: %v", err)
	}
	defer unix.Close(int(memfd))
	defer unix.Munmap(buf)

	// Set up the server and client.
	usrv := urpc.NewServer()
	server, err := NewAsyncFileServer(&testReadServer{
		path:         testPath,
		data:         data,
		maxReadBytes: 2 * chunkSize,
	})
	if err != nil {
		t.Fatalf("failed to create AsyncFileServer: %v", err)
	}
	usrv.Register(server)
	clientSock, serverSock, err := unet.SocketPair(false /* packet */)
	if err != nil {
		t.Fatalf("failed to create socketpair: %v", err)
	}
	client, err := NewAsyncFileClient(urpc.NewClient(clientSock))
	if err != nil {
		t.Fatalf("failed to create AsyncFileClient: %v", err)
	}
	defer client.DecRef()
	usrv.StartHandling(serverSock)

	// Open the file containing random data.
	ar, err := client.OpenRead(testPath)
	if err != nil {
		t.Fatalf("failed to open remote file: %v", err)
	}
	defer ar.Close()

	// Read the file using async vectorized reads.
	df, err := ar.RegisterDestinationFD(memfd, uint64(dataLen), nil)
	if err != nil {
		t.Fatalf("failed to register destination file: %v", err)
	}
	ids := uint32(0)
	off := 0
	done := 0
	var cs []stateio.Completion
	for done < dataLen {
		for ids != ^uint32(0) && off < dataLen {
			id := bits.TrailingZeros32(^ids)
			ids |= uint32(1) << id
			frs := []memmap.FileRange{
				{uint64(off), uint64(off) + chunkSize},
				{uint64(off) + chunkSize, uint64(off) + 2*chunkSize},
			}
			iovecs := []unix.Iovec{
				{Base: &buf[off], Len: chunkSize},
				{Base: &buf[off+chunkSize], Len: chunkSize},
			}
			ar.AddReadv(id, int64(off), 2*chunkSize, df, frs, iovecs)
			off += 2 * chunkSize
		}
		cs, err := ar.Wait(cs[:0], 1 /* minCompletions */)
		if err != nil {
			t.Fatalf("AsyncReader.Wait failed: %v", err)
		}
		for _, c := range cs {
			if c.Err != nil && c.Err != io.EOF {
				t.Fatalf("AsyncReader returned completion with error: %v", c.Err)
			}
			if c.N != 2*chunkSize {
				t.Fatalf("AsyncReader returned completion of %d bytes, want %d", c.N, 2*chunkSize)
			}
			ids &^= uint32(1) << c.ID
			done += 2 * chunkSize
		}
	}

	if !bytes.Equal(data, buf) {
		t.Errorf("bytes differ")
	}
}

func TestWrite(t *testing.T) {
	// Create the source file and fill it with random data.
	const chunkSize = 4096
	const dataLen = 1024 * chunkSize
	memfd, buf, err := stateio.CreateMappedMemoryFD("stateipc.TestReadv", dataLen)
	if err != nil {
		t.Fatalf("failed to create destination file: %v", err)
	}
	defer unix.Close(int(memfd))
	defer unix.Munmap(buf)
	_, _ = rand.Read(buf)

	// Set up the server and client.
	const testPath = "testfile"
	usrv := urpc.NewServer()
	tws := &testWriteServer{
		path:          testPath,
		maxWriteBytes: chunkSize,
	}
	server, err := NewAsyncFileServer(tws)
	if err != nil {
		t.Fatalf("failed to create AsyncFileServer: %v", err)
	}
	usrv.Register(server)
	clientSock, serverSock, err := unet.SocketPair(false /* packet */)
	if err != nil {
		t.Fatalf("failed to create socketpair: %v", err)
	}
	client, err := NewAsyncFileClient(urpc.NewClient(clientSock))
	if err != nil {
		t.Fatalf("failed to create AsyncFileClient: %v", err)
	}
	defer client.DecRef()
	usrv.StartHandling(serverSock)

	// Open the destination file.
	aw, err := client.OpenWrite(testPath)
	if err != nil {
		t.Fatalf("failed to open remote file: %v", err)
	}
	defer aw.Close()

	// Write the file using async writes.
	sf, err := aw.RegisterSourceFD(memfd, uint64(dataLen), nil)
	if err != nil {
		t.Fatalf("failed to register source file: %v", err)
	}
	ids := uint32(0)
	off := 0
	done := 0
	var cs []stateio.Completion
	for done < dataLen {
		for ids != ^uint32(0) && off < dataLen {
			id := bits.TrailingZeros32(^ids)
			ids |= uint32(1) << id
			aw.AddWrite(id, sf, memmap.FileRange{uint64(off), uint64(off) + chunkSize}, buf[off:off+chunkSize])
			off += chunkSize
		}
		cs, err := aw.Wait(cs[:0], 1 /* minCompletions */)
		if err != nil {
			t.Fatalf("AsyncWriter.Wait failed: %v", err)
		}
		for _, c := range cs {
			if c.Err != nil {
				t.Fatalf("AsyncWriter returned completion with error: %v", c.Err)
			}
			if c.N != chunkSize {
				t.Fatalf("AsyncWriter returned completion of %d bytes, want %d", c.N, chunkSize)
			}
			ids &^= uint32(1) << c.ID
			done += chunkSize
		}
	}
	if err := aw.Finalize(); err != nil {
		t.Fatalf("AsyncWriter.Finalize failed: %v", err)
	}

	if !bytes.Equal(buf, tws.buf.Bytes()) {
		t.Errorf("bytes differ")
	}
}

func TestWritev(t *testing.T) {
	// Create the source file and fill it with random data.
	const chunkSize = 4096
	const dataLen = 1024 * chunkSize
	memfd, buf, err := stateio.CreateMappedMemoryFD("stateipc.TestReadv", dataLen)
	if err != nil {
		t.Fatalf("failed to create destination file: %v", err)
	}
	defer unix.Close(int(memfd))
	defer unix.Munmap(buf)
	_, _ = rand.Read(buf)

	// Set up the server and client.
	const testPath = "testfile"
	usrv := urpc.NewServer()
	tws := &testWriteServer{
		path:          testPath,
		maxWriteBytes: 2 * chunkSize,
	}
	server, err := NewAsyncFileServer(tws)
	if err != nil {
		t.Fatalf("failed to create AsyncFileServer: %v", err)
	}
	usrv.Register(server)
	clientSock, serverSock, err := unet.SocketPair(false /* packet */)
	if err != nil {
		t.Fatalf("failed to create socketpair: %v", err)
	}
	client, err := NewAsyncFileClient(urpc.NewClient(clientSock))
	if err != nil {
		t.Fatalf("failed to create AsyncFileClient: %v", err)
	}
	defer client.DecRef()
	usrv.StartHandling(serverSock)

	// Open the destination file.
	aw, err := client.OpenWrite(testPath)
	if err != nil {
		t.Fatalf("failed to open remote file: %v", err)
	}
	defer aw.Close()

	// Write the file using async writes.
	sf, err := aw.RegisterSourceFD(memfd, uint64(dataLen), nil)
	if err != nil {
		t.Fatalf("failed to register source file: %v", err)
	}
	ids := uint32(0)
	off := 0
	done := 0
	var cs []stateio.Completion
	for done < dataLen {
		for ids != ^uint32(0) && off < dataLen {
			id := bits.TrailingZeros32(^ids)
			ids |= uint32(1) << id
			frs := []memmap.FileRange{
				{uint64(off), uint64(off) + chunkSize},
				{uint64(off) + chunkSize, uint64(off) + 2*chunkSize},
			}
			iovecs := []unix.Iovec{
				{Base: &buf[off], Len: chunkSize},
				{Base: &buf[off+chunkSize], Len: chunkSize},
			}
			aw.AddWritev(id, 2*chunkSize, sf, frs, iovecs)
			off += 2 * chunkSize
		}
		cs, err := aw.Wait(cs[:0], 1 /* minCompletions */)
		if err != nil {
			t.Fatalf("AsyncWriter.Wait failed: %v", err)
		}
		for _, c := range cs {
			if c.Err != nil {
				t.Fatalf("AsyncWriter returned completion with error: %v", c.Err)
			}
			if c.N != 2*chunkSize {
				t.Fatalf("AsyncWriter returned completion of %d bytes, want %d", c.N, 2*chunkSize)
			}
			ids &^= uint32(1) << c.ID
			done += 2 * chunkSize
		}
	}
	if err := aw.Finalize(); err != nil {
		t.Fatalf("AsyncWriter.Finalize failed: %v", err)
	}

	if !bytes.Equal(buf, tws.buf.Bytes()) {
		t.Errorf("bytes differ")
	}
}

func TestClientWatchdog(t *testing.T) {
	// Create random data.
	const testPath = "testfile"
	const chunkSize = 4096
	const dataLen = 2 * chunkSize
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)

	// Create the destination file.
	memfd, buf, err := stateio.CreateMappedMemoryFD("stateipc.TestClientWatchdog", dataLen)
	if err != nil {
		t.Fatalf("failed to create destination file: %v", err)
	}
	defer unix.Close(int(memfd))
	defer unix.Munmap(buf)

	// Set up the server and client.
	usrv := urpc.NewServer()
	server, err := NewAsyncFileServer(&testReadServer{
		path:         testPath,
		data:         data,
		maxReadBytes: chunkSize,
	})
	if err != nil {
		t.Fatalf("failed to create AsyncFileServer: %v", err)
	}
	usrv.Register(server)
	clientSock, serverSock, err := unet.SocketPair(false /* packet */)
	if err != nil {
		t.Fatalf("failed to create socketpair: %v", err)
	}
	client, err := NewAsyncFileClient(urpc.NewClient(clientSock))
	if err != nil {
		t.Fatalf("failed to create AsyncFileClient: %v", err)
	}
	defer client.DecRef()
	usrv.StartHandling(serverSock)

	// Open the file containing random data.
	ar, err := client.OpenRead(testPath)
	if err != nil {
		t.Fatalf("failed to open remote file: %v", err)
	}
	defer ar.Close()

	// Read one chunk from the file.
	df, err := ar.RegisterDestinationFD(memfd, uint64(dataLen), nil)
	if err != nil {
		t.Fatalf("failed to register destination file: %v", err)
	}
	ar.AddRead(0 /* id */, 0 /* off */, df, memmap.FileRange{0, chunkSize}, buf[:chunkSize])
	cs, err := ar.Wait(nil, 1 /* minCompletions */)
	if err != nil {
		t.Fatalf("AsyncReader.Wait before shutdown failed: %v", err)
	}
	if len(cs) != 1 {
		t.Fatalf("AsyncReader.Wait before shutdown returned %d completions, want 1", len(cs))
	}
	if c := cs[0]; c.ID != 0 || c.N != chunkSize || c.Err != nil {
		t.Errorf("AsyncReader.Wait before shutdown returned completion with ID=%d, N=%d, Err=%v, want ID=0, N=%d, Err=nil", c.ID, c.N, c.Err, chunkSize)
	}

	// Force connection shutdown and give the watchdog some time to respond.
	if err := serverSock.Shutdown(); err != nil {
		t.Fatalf("failed to shut down server socket: %v", err)
	}
	time.Sleep(time.Second)

	// Attempt to read the second chunk from the file and expect error.
	ar.AddRead(0 /* id */, chunkSize, df, memmap.FileRange{chunkSize, chunkSize * 2}, buf[chunkSize:chunkSize*2])
	cs, err = ar.Wait(cs[:0], 1 /* minCompletions */)
	if err == nil {
		t.Errorf("AsyncReader.Wait after shutdown got error nil, completions: %+v", cs)
	}
	t.Logf("AsyncReader.Wait after shutdown got error: %v", err)
}
