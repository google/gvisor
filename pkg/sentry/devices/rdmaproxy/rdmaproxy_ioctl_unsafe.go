// Copyright 2024 The gVisor Authors.
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

package rdmaproxy

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	rdmaIoctlMagic = 0x1b

	ibUverbsIoctlHdrSize = 24
	ibUverbsAttrSize     = 16

	// Attrs with data larger than 8 bytes store a userspace pointer in
	// the data field; smaller values are stored inline.
	ibUverbsAttrInlineMax = 8
)

// RDMA_VERBS_IOCTL = _IOWR(0x1b, 1, struct ib_uverbs_ioctl_hdr)
var rdmaVerbsIoctl = linux.IOWR(rdmaIoctlMagic, 1, ibUverbsIoctlHdrSize)

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *uverbsFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := args[1].Uint()
	argPtr := args[2].Pointer()

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		log.Warningf("rdmaproxy: ioctl called without task context")
		return 0, unix.EINVAL
	}

	if cmd == rdmaVerbsIoctl {
		return fd.handleRDMAVerbsIoctl(t, argPtr)
	}
	return 0, linuxerr.ENOSYS
}

// handleRDMAVerbsIoctl handles the modern RDMA_VERBS_IOCTL which uses a
// self-describing header + variable-length attribute array. Each attribute's
// data field is either inline (len <= 8) or a pointer to sandbox userspace
// memory (len > 8). We must copy those pointed-to buffers into the sentry's
// address space before forwarding to the host kernel.
func (fd *uverbsFD) handleRDMAVerbsIoctl(t *kernel.Task, argPtr hostarch.Addr) (uintptr, error) {
	// Read the base header to learn the total length.
	var hdrBuf [ibUverbsIoctlHdrSize]byte
	if _, err := t.CopyInBytes(argPtr, hdrBuf[:]); err != nil {
		return 0, err
	}

	length := binary.LittleEndian.Uint16(hdrBuf[0:2])
	numAttrs := binary.LittleEndian.Uint16(hdrBuf[6:8])

	expectedLen := uint16(ibUverbsIoctlHdrSize) + numAttrs*uint16(ibUverbsAttrSize)
	if length != expectedLen || length > hostarch.PageSize {
		return 0, linuxerr.EINVAL
	}

	// Read the full header + attrs buffer.
	buf := make([]byte, length)
	if _, err := t.CopyInBytes(argPtr, buf); err != nil {
		return 0, err
	}

	// Walk attrs and rewrite any data pointers that point into sandbox
	// userspace. Attrs with len <= 8 store inline data in the data field
	// and need no translation.
	type rewrite struct {
		attrOff  int
		origData uint64
		sentry   []byte
	}
	var rewrites []rewrite

	for i := 0; i < int(numAttrs); i++ {
		off := ibUverbsIoctlHdrSize + i*ibUverbsAttrSize
		attrLen := binary.LittleEndian.Uint16(buf[off+2 : off+4])

		if attrLen > ibUverbsAttrInlineMax {
			dataPtr := binary.LittleEndian.Uint64(buf[off+8 : off+16])
			sb := make([]byte, attrLen)
			if _, err := t.CopyInBytes(hostarch.Addr(dataPtr), sb); err != nil {
				return 0, err
			}
			binary.LittleEndian.PutUint64(buf[off+8:off+16],
				uint64(uintptr(unsafe.Pointer(&sb[0]))))
			rewrites = append(rewrites, rewrite{
				attrOff:  off,
				origData: dataPtr,
				sentry:   sb,
			})
		}
	}

	// Forward to host.
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL,
		uintptr(fd.hostFD), uintptr(rdmaVerbsIoctl),
		uintptr(unsafe.Pointer(&buf[0])))

	// Copy output data back and restore original pointers.
	for _, rw := range rewrites {
		// Always copy back — the host may have written output data.
		t.CopyOutBytes(hostarch.Addr(rw.origData), rw.sentry)
		binary.LittleEndian.PutUint64(buf[rw.attrOff+8:rw.attrOff+16], rw.origData)
	}
	// Copy the header+attrs back so the app sees updated len/flags.
	t.CopyOutBytes(argPtr, buf)

	if errno != 0 {
		return n, errno
	}
	return n, nil
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *uverbsFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return vfs.GenericProxyDeviceConfigureMMap(&fd.vfsfd, fd, opts)
}

// Translate implements memmap.Mappable.Translate.
func (fd *uverbsFD) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	return []memmap.Translation{
		{
			Source: optional,
			File:   &fd.memmapFile,
			Offset: optional.Start,
			Perms:  hostarch.AnyAccess,
		},
	}, nil
}
