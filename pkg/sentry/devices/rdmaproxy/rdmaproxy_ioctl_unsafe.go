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
	// the data field; smaller values are stored inline — UNLESS the
	// VALID_OUTPUT flag is set, in which case data is always a pointer.
	ibUverbsAttrInlineMax = 8

	// uverbsAttrFValidOutput is UVERBS_ATTR_F_VALID_OUTPUT. When set,
	// the kernel writes output via the pointer in the data field,
	// so the data field is a pointer even when len <= 8.
	uverbsAttrFValidOutput = 0x2
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
	log.Warningf("rdmaproxy: unhandled ioctl cmd=0x%x (magic=0x%x nr=%d size=%d) on hostFD=%d",
		cmd, (cmd>>8)&0xff, cmd&0xff, (cmd>>16)&0x3fff, fd.hostFD)
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
		log.Warningf("rdmaproxy: ioctl CopyIn header from %#x: %v", argPtr, err)
		return 0, err
	}

	length := binary.LittleEndian.Uint16(hdrBuf[0:2])
	objectID := binary.LittleEndian.Uint16(hdrBuf[2:4])
	methodID := binary.LittleEndian.Uint16(hdrBuf[4:6])
	numAttrs := binary.LittleEndian.Uint16(hdrBuf[6:8])
	reserved1 := binary.LittleEndian.Uint64(hdrBuf[8:16])
	driverID := binary.LittleEndian.Uint32(hdrBuf[16:20])

	log.Infof("rdmaproxy: IOCTL hostFD=%d obj=0x%04x method=%d attrs=%d len=%d reserved=%#x driver=%d",
		fd.hostFD, objectID, methodID, numAttrs, length, reserved1, driverID)

	expectedLen := uint16(ibUverbsIoctlHdrSize) + numAttrs*uint16(ibUverbsAttrSize)
	if length != expectedLen || length > hostarch.PageSize {
		log.Warningf("rdmaproxy: ioctl bad header: length=%d expected=%d (numAttrs=%d)",
			length, expectedLen, numAttrs)
		return 0, linuxerr.EINVAL
	}

	// Read the full header + attrs buffer.
	buf := make([]byte, length)
	if _, err := t.CopyInBytes(argPtr, buf); err != nil {
		log.Warningf("rdmaproxy: ioctl CopyIn full buffer (%d bytes) from %#x: %v",
			length, argPtr, err)
		return 0, err
	}

	// Walk attrs and rewrite sandbox pointers. The data field is a pointer
	// when EITHER:
	//   - len > 8 (data too large to fit inline), OR
	//   - UVERBS_ATTR_F_VALID_OUTPUT is set (kernel writes back via the
	//     pointer regardless of len).
	// Otherwise (input-only, len <= 8) data is stored inline in the field.
	type rewrite struct {
		attrOff  int
		origData uint64
		sentry   []byte
	}
	var rewrites []rewrite

	for i := 0; i < int(numAttrs); i++ {
		off := ibUverbsIoctlHdrSize + i*ibUverbsAttrSize
		attrID := binary.LittleEndian.Uint16(buf[off : off+2])
		attrLen := binary.LittleEndian.Uint16(buf[off+2 : off+4])
		attrFlags := binary.LittleEndian.Uint16(buf[off+4 : off+6])
		attrData := binary.LittleEndian.Uint64(buf[off+8 : off+16])

		isOutput := attrFlags&uverbsAttrFValidOutput != 0
		needsRewrite := attrLen > ibUverbsAttrInlineMax || (isOutput && attrLen > 0)

		if needsRewrite {
			log.Infof("rdmaproxy:   attr[%d] id=0x%04x len=%d flags=0x%04x data=ptr:%#016x (rewrite, output=%v)",
				i, attrID, attrLen, attrFlags, attrData, isOutput)
			sb := make([]byte, attrLen)
			if _, err := t.CopyInBytes(hostarch.Addr(attrData), sb); err != nil {
				log.Warningf("rdmaproxy:   attr[%d] CopyIn %d bytes from %#x: %v",
					i, attrLen, attrData, err)
				return 0, err
			}
			if attrLen <= 64 {
				log.Infof("rdmaproxy:   attr[%d] data: %x", i, sb)
			} else {
				log.Infof("rdmaproxy:   attr[%d] data (first 64): %x ...", i, sb[:64])
			}
			binary.LittleEndian.PutUint64(buf[off+8:off+16],
				uint64(uintptr(unsafe.Pointer(&sb[0]))))
			rewrites = append(rewrites, rewrite{
				attrOff:  off,
				origData: attrData,
				sentry:   sb,
			})
		} else {
			log.Infof("rdmaproxy:   attr[%d] id=0x%04x len=%d flags=0x%04x data=inline:%#016x",
				i, attrID, attrLen, attrFlags, attrData)
		}
	}

	log.Infof("rdmaproxy: forwarding ioctl to host (hostFD=%d, %d rewrites)", fd.hostFD, len(rewrites))

	// Forward to host.
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL,
		uintptr(fd.hostFD), uintptr(rdmaVerbsIoctl),
		uintptr(unsafe.Pointer(&buf[0])))

	if errno != 0 {
		log.Infof("rdmaproxy: host ioctl returned n=%d errno=%d (%v)", n, errno, errno)
	} else {
		log.Infof("rdmaproxy: host ioctl returned n=%d OK", n)
	}

	// Copy output data back and restore original pointers.
	for _, rw := range rewrites {
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
	log.Infof("rdmaproxy: mmap hostFD=%d len=%d offset=0x%x perms=%v private=%v",
		fd.hostFD, opts.Length, opts.Offset, opts.Perms, opts.Private)
	err := vfs.GenericProxyDeviceConfigureMMap(&fd.vfsfd, fd, opts)
	if err != nil {
		log.Warningf("rdmaproxy: mmap hostFD=%d: %v", fd.hostFD, err)
	}
	return err
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
