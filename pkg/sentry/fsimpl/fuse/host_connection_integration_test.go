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

package fuse

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// testFUSEServer implements a minimal FUSE protocol server over a socketpair.
// It handles the operations needed to exercise basic filesystem I/O:
// INIT, GETATTR, LOOKUP, OPEN, READ, WRITE, FLUSH, RELEASE.
//
// The server is backed by a real directory on the host filesystem.
type testFUSEServer struct {
	fd        int
	backDir   string
	nextFh    uint64
	openFiles map[uint64]*os.File
}

func newTestFUSEServer(fd int, backDir string) *testFUSEServer {
	return &testFUSEServer{
		fd:        fd,
		backDir:   backDir,
		nextFh:    1,
		openFiles: make(map[uint64]*os.File),
	}
}

func (s *testFUSEServer) serve(t *testing.T, done chan struct{}) {
	t.Helper()
	defer close(done)
	for {
		buf := make([]byte, 64*1024)
		n, err := unix.Read(s.fd, buf)
		if err != nil || n == 0 {
			return
		}
		if n < int(linux.SizeOfFUSEHeaderIn) {
			t.Errorf("fuse server: short request %d bytes", n)
			return
		}
		buf = buf[:n]

		var hdr linux.FUSEHeaderIn
		hdr.UnmarshalUnsafe(buf[:linux.SizeOfFUSEHeaderIn])
		payload := buf[linux.SizeOfFUSEHeaderIn:]

		resp := s.handleRequest(&hdr, payload)
		if resp == nil {
			continue
		}
		if _, err := unix.Write(s.fd, resp); err != nil {
			return
		}
	}
}

func (s *testFUSEServer) handleRequest(hdr *linux.FUSEHeaderIn, payload []byte) []byte {
	switch hdr.Opcode {
	case linux.FUSE_INIT:
		return s.handleInit(hdr)
	case linux.FUSE_GETATTR:
		return s.handleGetAttr(hdr)
	case linux.FUSE_LOOKUP:
		return s.handleLookup(hdr, payload)
	case linux.FUSE_OPEN:
		return s.handleOpen(hdr, payload)
	case linux.FUSE_READ:
		return s.handleRead(hdr, payload)
	case linux.FUSE_WRITE:
		return s.handleWrite(hdr, payload)
	case linux.FUSE_FLUSH:
		return s.replyOK(hdr)
	case linux.FUSE_RELEASE:
		return s.handleRelease(hdr, payload)
	case linux.FUSE_ACCESS:
		return s.replyOK(hdr)
	default:
		return s.replyError(hdr, -int32(unix.ENOSYS))
	}
}

func (s *testFUSEServer) handleInit(hdr *linux.FUSEHeaderIn) []byte {
	out := linux.FUSEInitOut{
		Major:    linux.FUSE_KERNEL_VERSION,
		Minor:    linux.FUSE_KERNEL_MINOR_VERSION,
		MaxWrite: 65536,
	}
	return s.marshalReply(hdr, &out)
}

func (s *testFUSEServer) handleGetAttr(hdr *linux.FUSEHeaderIn) []byte {
	path := s.backDir
	if hdr.NodeID != linux.FUSE_ROOT_ID {
		path = filepath.Join(s.backDir, "testfile")
	}
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return s.replyError(hdr, -int32(unix.ENOENT))
	}
	out := linux.FUSEAttrOut{
		AttrValid: 1,
		Attr:      statToFUSEAttr(stat, hdr.NodeID),
	}
	return s.marshalReply(hdr, &out)
}

func (s *testFUSEServer) handleLookup(hdr *linux.FUSEHeaderIn, payload []byte) []byte {
	nameEnd := 0
	for nameEnd < len(payload) && payload[nameEnd] != 0 {
		nameEnd++
	}
	name := string(payload[:nameEnd])

	path := filepath.Join(s.backDir, name)
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return s.replyError(hdr, -int32(unix.ENOENT))
	}

	const childNodeID uint64 = 2
	out := linux.FUSEEntryOut{
		NodeID:     childNodeID,
		Generation: 1,
		EntryValid: 1,
		AttrValid:  1,
		Attr:       statToFUSEAttr(stat, childNodeID),
	}
	return s.marshalReply(hdr, &out)
}

func (s *testFUSEServer) handleOpen(hdr *linux.FUSEHeaderIn, payload []byte) []byte {
	var in linux.FUSEOpenIn
	in.UnmarshalUnsafe(payload[:in.SizeBytes()])

	path := filepath.Join(s.backDir, "testfile")
	flags := int(in.Flags) & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return s.replyError(hdr, -int32(unix.EIO))
	}

	fh := s.nextFh
	s.nextFh++
	s.openFiles[fh] = f

	out := linux.FUSEOpenOut{
		Fh:       fh,
		OpenFlag: linux.FOPEN_DIRECT_IO,
	}
	return s.marshalReply(hdr, &out)
}

func (s *testFUSEServer) handleRead(hdr *linux.FUSEHeaderIn, payload []byte) []byte {
	var in linux.FUSEReadIn
	in.UnmarshalUnsafe(payload[:in.SizeBytes()])

	f, ok := s.openFiles[in.Fh]
	if !ok {
		return s.replyError(hdr, -int32(unix.EBADF))
	}

	data := make([]byte, in.Size)
	n, err := f.ReadAt(data, int64(in.Offset))
	if err != nil && n == 0 {
		return s.dataReply(hdr, nil)
	}
	return s.dataReply(hdr, data[:n])
}

func (s *testFUSEServer) handleWrite(hdr *linux.FUSEHeaderIn, payload []byte) []byte {
	var in linux.FUSEWriteIn
	in.UnmarshalUnsafe(payload[:in.SizeBytes()])

	f, ok := s.openFiles[in.Fh]
	if !ok {
		return s.replyError(hdr, -int32(unix.EBADF))
	}

	writeData := payload[in.SizeBytes():]
	n, err := f.WriteAt(writeData, int64(in.Offset))
	if err != nil {
		return s.replyError(hdr, -int32(unix.EIO))
	}

	out := linux.FUSEWriteOut{Size: uint32(n)}
	return s.marshalReply(hdr, &out)
}

func (s *testFUSEServer) handleRelease(hdr *linux.FUSEHeaderIn, payload []byte) []byte {
	var in linux.FUSEReleaseIn
	in.UnmarshalUnsafe(payload[:in.SizeBytes()])
	if f, ok := s.openFiles[in.Fh]; ok {
		f.Close()
		delete(s.openFiles, in.Fh)
	}
	return s.replyOK(hdr)
}

type marshalUnsafer interface {
	SizeBytes() int
	MarshalUnsafe(dst []byte) []byte
}

func (s *testFUSEServer) marshalReply(hdr *linux.FUSEHeaderIn, payload marshalUnsafer) []byte {
	hdrSize := int(linux.SizeOfFUSEHeaderOut)
	payloadSize := payload.SizeBytes()
	buf := make([]byte, hdrSize+payloadSize)
	outHdr := linux.FUSEHeaderOut{
		Len:    uint32(hdrSize + payloadSize),
		Unique: hdr.Unique,
	}
	outHdr.MarshalUnsafe(buf[:hdrSize])
	payload.MarshalUnsafe(buf[hdrSize:])
	return buf
}

func (s *testFUSEServer) dataReply(hdr *linux.FUSEHeaderIn, data []byte) []byte {
	hdrSize := int(linux.SizeOfFUSEHeaderOut)
	buf := make([]byte, hdrSize+len(data))
	outHdr := linux.FUSEHeaderOut{
		Len:    uint32(hdrSize + len(data)),
		Unique: hdr.Unique,
	}
	outHdr.MarshalUnsafe(buf[:hdrSize])
	copy(buf[hdrSize:], data)
	return buf
}

func (s *testFUSEServer) replyOK(hdr *linux.FUSEHeaderIn) []byte {
	return s.replyError(hdr, 0)
}

func (s *testFUSEServer) replyError(hdr *linux.FUSEHeaderIn, errno int32) []byte {
	hdrSize := int(linux.SizeOfFUSEHeaderOut)
	buf := make([]byte, hdrSize)
	outHdr := linux.FUSEHeaderOut{
		Len:    uint32(hdrSize),
		Error:  errno,
		Unique: hdr.Unique,
	}
	outHdr.MarshalUnsafe(buf)
	return buf
}

func statToFUSEAttr(stat unix.Stat_t, ino uint64) linux.FUSEAttr {
	return linux.FUSEAttr{
		Ino:       ino,
		Size:      uint64(stat.Size),
		Blocks:    uint64(stat.Blocks),
		Atime:     uint64(stat.Atim.Sec),
		Mtime:     uint64(stat.Mtim.Sec),
		Ctime:     uint64(stat.Ctim.Sec),
		AtimeNsec: uint32(stat.Atim.Nsec),
		MtimeNsec: uint32(stat.Mtim.Nsec),
		CtimeNsec: uint32(stat.Ctim.Nsec),
		Mode:      stat.Mode,
		Nlink:     uint32(stat.Nlink),
		UID:       stat.Uid,
		GID:       stat.Gid,
		BlkSize:   uint32(stat.Blksize),
	}
}

// newTestHostFUSEConnection creates a socketpair, starts a FUSE protocol
// server on one end backed by backDir, and returns a hostConnection using
// the other end. The connection is fully initialized via FUSE_INIT.
func newTestHostFUSEConnection(t *testing.T, backDir string) (*hostConnection, chan struct{}, func()) {
	t.Helper()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}

	server := newTestFUSEServer(fds[1], backDir)
	serverDone := make(chan struct{})
	go server.serve(t, serverDone)

	fsopts := filesystemOptions{
		maxActiveRequests: maxActiveRequestsDefault,
		maxRead:           65536,
	}
	conn, err := newFUSEConnectionOpts(&fsopts)
	if err != nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
		t.Fatalf("newFUSEConnectionOpts: %v", err)
	}
	hc := newHostConnection(conn, int32(fds[0]))

	cleanup := func() {
		unix.Close(fds[0])
		unix.Close(fds[1])
		<-serverDone
	}
	return hc, serverDone, cleanup
}

// TestHostFUSEReadFile exercises a full FUSE read through the host passthrough
// path: INIT → LOOKUP → OPEN → READ → RELEASE, with the FUSE server backed
// by a real file on the host.
func TestHostFUSEReadFile(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	backDir := t.TempDir()
	testData := "hello from the host FUSE server\n"
	if err := os.WriteFile(filepath.Join(backDir, "testfile"), []byte(testData), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	hc, _, cleanup := newTestHostFUSEConnection(t, backDir)
	defer cleanup()

	creds := auth.CredentialsFromContext(s.Ctx)

	// FUSE_INIT
	if err := hc.InitSend(creds, 1, true); err != nil {
		t.Fatalf("InitSend: %v", err)
	}
	if !hc.conn.isInitialized() {
		t.Fatal("connection not initialized after InitSend")
	}

	// FUSE_LOOKUP "testfile"
	lookupIn := linux.FUSELookupIn{Name: linux.CString("testfile")}
	lookupReq := hc.conn.NewRequest(creds, 1, linux.FUSE_ROOT_ID, linux.FUSE_LOOKUP, &lookupIn)
	lookupResp, err := hc.Call(s.Ctx, lookupReq)
	if err != nil {
		t.Fatalf("LOOKUP Call: %v", err)
	}
	if lookupResp.Error() != nil {
		t.Fatalf("LOOKUP error: %v", lookupResp.Error())
	}
	var entryOut linux.FUSEEntryOut
	if err := lookupResp.UnmarshalPayload(&entryOut); err != nil {
		t.Fatalf("LOOKUP unmarshal: %v", err)
	}
	if entryOut.NodeID == 0 {
		t.Fatal("LOOKUP returned nodeID 0")
	}

	// FUSE_OPEN
	openIn := linux.FUSEOpenIn{Flags: uint32(linux.O_RDONLY)}
	openReq := hc.conn.NewRequest(creds, 1, entryOut.NodeID, linux.FUSE_OPEN, &openIn)
	openResp, err := hc.Call(s.Ctx, openReq)
	if err != nil {
		t.Fatalf("OPEN Call: %v", err)
	}
	if openResp.Error() != nil {
		t.Fatalf("OPEN error: %v", openResp.Error())
	}
	var openOut linux.FUSEOpenOut
	if err := openResp.UnmarshalPayload(&openOut); err != nil {
		t.Fatalf("OPEN unmarshal: %v", err)
	}

	// FUSE_READ
	readIn := linux.FUSEReadIn{
		Fh:     openOut.Fh,
		Offset: 0,
		Size:   uint32(hostarch.PageSize),
	}
	readReq := hc.conn.NewRequest(creds, 1, entryOut.NodeID, linux.FUSE_READ, &readIn)
	readResp, err := hc.Call(s.Ctx, readReq)
	if err != nil {
		t.Fatalf("READ Call: %v", err)
	}
	if readResp.Error() != nil {
		t.Fatalf("READ error: %v", readResp.Error())
	}
	readData := readResp.data[readResp.hdr.SizeBytes():]
	if string(readData) != testData {
		t.Fatalf("READ data: got %q, want %q", string(readData), testData)
	}

	// FUSE_RELEASE
	releaseIn := linux.FUSEReleaseIn{Fh: openOut.Fh}
	releaseReq := hc.conn.NewRequest(creds, 1, entryOut.NodeID, linux.FUSE_RELEASE, &releaseIn)
	releaseResp, err := hc.Call(s.Ctx, releaseReq)
	if err != nil {
		t.Fatalf("RELEASE Call: %v", err)
	}
	if releaseResp.Error() != nil {
		t.Fatalf("RELEASE error: %v", releaseResp.Error())
	}
}

// TestHostFUSEWriteFile exercises a full FUSE write through the host
// passthrough path: INIT → LOOKUP → OPEN → WRITE → RELEASE, then verifies
// the data was written to the backing file on the host.
func TestHostFUSEWriteFile(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	backDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(backDir, "testfile"), nil, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	hc, _, cleanup := newTestHostFUSEConnection(t, backDir)
	defer cleanup()

	creds := auth.CredentialsFromContext(s.Ctx)

	// FUSE_INIT
	if err := hc.InitSend(creds, 1, true); err != nil {
		t.Fatalf("InitSend: %v", err)
	}

	// FUSE_LOOKUP "testfile"
	lookupIn := linux.FUSELookupIn{Name: linux.CString("testfile")}
	lookupReq := hc.conn.NewRequest(creds, 1, linux.FUSE_ROOT_ID, linux.FUSE_LOOKUP, &lookupIn)
	lookupResp, err := hc.Call(s.Ctx, lookupReq)
	if err != nil {
		t.Fatalf("LOOKUP Call: %v", err)
	}
	if lookupResp.Error() != nil {
		t.Fatalf("LOOKUP error: %v", lookupResp.Error())
	}
	var entryOut linux.FUSEEntryOut
	if err := lookupResp.UnmarshalPayload(&entryOut); err != nil {
		t.Fatalf("LOOKUP unmarshal: %v", err)
	}

	// FUSE_OPEN for writing
	openIn := linux.FUSEOpenIn{Flags: uint32(linux.O_WRONLY)}
	openReq := hc.conn.NewRequest(creds, 1, entryOut.NodeID, linux.FUSE_OPEN, &openIn)
	openResp, err := hc.Call(s.Ctx, openReq)
	if err != nil {
		t.Fatalf("OPEN Call: %v", err)
	}
	if openResp.Error() != nil {
		t.Fatalf("OPEN error: %v", openResp.Error())
	}
	var openOut linux.FUSEOpenOut
	if err := openResp.UnmarshalPayload(&openOut); err != nil {
		t.Fatalf("OPEN unmarshal: %v", err)
	}

	// FUSE_WRITE
	writeData := []byte("written via host FUSE passthrough\n")
	writeIn := linux.FUSEWritePayloadIn{
		Header: linux.FUSEWriteIn{
			Fh:     openOut.Fh,
			Offset: 0,
			Size:   uint32(len(writeData)),
		},
		Payload: writeData,
	}
	writeReq := hc.conn.NewRequest(creds, 1, entryOut.NodeID, linux.FUSE_WRITE, &writeIn)
	writeResp, err := hc.Call(s.Ctx, writeReq)
	if err != nil {
		t.Fatalf("WRITE Call: %v", err)
	}
	if writeResp.Error() != nil {
		t.Fatalf("WRITE error: %v", writeResp.Error())
	}
	var writeOut linux.FUSEWriteOut
	if err := writeResp.UnmarshalPayload(&writeOut); err != nil {
		t.Fatalf("WRITE unmarshal: %v", err)
	}
	if writeOut.Size != uint32(len(writeData)) {
		t.Fatalf("WRITE size: got %d, want %d", writeOut.Size, len(writeData))
	}

	// FUSE_RELEASE
	releaseIn := linux.FUSEReleaseIn{Fh: openOut.Fh}
	releaseReq := hc.conn.NewRequest(creds, 1, entryOut.NodeID, linux.FUSE_RELEASE, &releaseIn)
	hc.Call(s.Ctx, releaseReq)

	// Verify the data reached the host filesystem.
	got, err := os.ReadFile(filepath.Join(backDir, "testfile"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(writeData) {
		t.Fatalf("backing file: got %q, want %q", string(got), string(writeData))
	}
}
