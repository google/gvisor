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

// Package fusehost implements a minimal FUSE protocol server for testing
// the host FD passthrough path. It forwards all operations to a backing
// directory on the host filesystem.
package fusehost

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// Serve runs a FUSE protocol server on fd, backed by the host directory
// backDir. It handles requests until the connection is closed or an error
// occurs. Intended to be called as a goroutine.
func Serve(fd int, backDir string) {
	s := &server{
		fd:        fd,
		backDir:   backDir,
		nextFh:    1,
		openFiles: make(map[uint64]*os.File),
	}
	s.serve()
}

type server struct {
	fd        int
	backDir   string
	nextFh    uint64
	openFiles map[uint64]*os.File
}

func (s *server) serve() {
	for {
		buf := make([]byte, 64*1024)
		n, err := unix.Read(s.fd, buf)
		if err != nil || n == 0 {
			return
		}
		if n < int(linux.SizeOfFUSEHeaderIn) {
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

func (s *server) handleRequest(hdr *linux.FUSEHeaderIn, payload []byte) []byte {
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
	case linux.FUSE_STATFS:
		return s.handleStatFS(hdr)
	default:
		return s.replyError(hdr, -int32(unix.ENOSYS))
	}
}

func (s *server) handleInit(hdr *linux.FUSEHeaderIn) []byte {
	out := linux.FUSEInitOut{
		Major:    linux.FUSE_KERNEL_VERSION,
		Minor:    linux.FUSE_KERNEL_MINOR_VERSION,
		MaxWrite: 65536,
		Flags:    linux.FUSE_BIG_WRITES,
	}
	return s.marshalReply(hdr, &out)
}

func (s *server) handleGetAttr(hdr *linux.FUSEHeaderIn) []byte {
	path := s.nodeIDToPath(hdr.NodeID)
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

func (s *server) handleLookup(hdr *linux.FUSEHeaderIn, payload []byte) []byte {
	nameEnd := 0
	for nameEnd < len(payload) && payload[nameEnd] != 0 {
		nameEnd++
	}
	name := string(payload[:nameEnd])

	path := filepath.Join(s.nodeIDToPath(hdr.NodeID), name)
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return s.replyError(hdr, -int32(unix.ENOENT))
	}

	out := linux.FUSEEntryOut{
		NodeID:     stat.Ino,
		Generation: 1,
		EntryValid: 1,
		AttrValid:  1,
		Attr:       statToFUSEAttr(stat, stat.Ino),
	}
	return s.marshalReply(hdr, &out)
}

func (s *server) handleOpen(hdr *linux.FUSEHeaderIn, payload []byte) []byte {
	var in linux.FUSEOpenIn
	in.UnmarshalUnsafe(payload[:in.SizeBytes()])

	path := s.nodeIDToPath(hdr.NodeID)
	flags := int(in.Flags) & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_TRUNC)
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

func (s *server) handleRead(hdr *linux.FUSEHeaderIn, payload []byte) []byte {
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

func (s *server) handleWrite(hdr *linux.FUSEHeaderIn, payload []byte) []byte {
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

func (s *server) handleRelease(hdr *linux.FUSEHeaderIn, payload []byte) []byte {
	var in linux.FUSEReleaseIn
	in.UnmarshalUnsafe(payload[:in.SizeBytes()])
	if f, ok := s.openFiles[in.Fh]; ok {
		f.Close()
		delete(s.openFiles, in.Fh)
	}
	return s.replyOK(hdr)
}

func (s *server) handleStatFS(hdr *linux.FUSEHeaderIn) []byte {
	var statfs unix.Statfs_t
	if err := unix.Statfs(s.backDir, &statfs); err != nil {
		return s.replyError(hdr, -int32(unix.EIO))
	}
	out := linux.FUSEStatfsOut{
		Blocks:          statfs.Blocks,
		BlocksFree:      statfs.Bfree,
		BlocksAvailable: statfs.Bavail,
		Files:           statfs.Files,
		FilesFree:       statfs.Ffree,
		BlockSize:       uint32(statfs.Bsize),
		NameLength:      uint32(statfs.Namelen),
		FragmentSize:    uint32(statfs.Frsize),
	}
	return s.marshalReply(hdr, &out)
}

func (s *server) nodeIDToPath(nodeID uint64) string {
	if nodeID == linux.FUSE_ROOT_ID {
		return s.backDir
	}
	entries, err := os.ReadDir(s.backDir)
	if err != nil {
		return s.backDir
	}
	for _, e := range entries {
		path := filepath.Join(s.backDir, e.Name())
		var stat unix.Stat_t
		if err := unix.Stat(path, &stat); err == nil && stat.Ino == nodeID {
			return path
		}
	}
	return s.backDir
}

type marshalUnsafer interface {
	SizeBytes() int
	MarshalUnsafe(dst []byte) []byte
}

func (s *server) marshalReply(hdr *linux.FUSEHeaderIn, payload marshalUnsafer) []byte {
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

func (s *server) dataReply(hdr *linux.FUSEHeaderIn, data []byte) []byte {
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

func (s *server) replyOK(hdr *linux.FUSEHeaderIn) []byte {
	return s.replyError(hdr, 0)
}

func (s *server) replyError(hdr *linux.FUSEHeaderIn, errno int32) []byte {
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
