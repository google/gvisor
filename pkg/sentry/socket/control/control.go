// Copyright 2018 The gVisor Authors.
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

// Package control provides internal representations of socket control
// messages.
package control

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
)

const maxInt = int(^uint(0) >> 1)

// SCMCredentials represents a SCM_CREDENTIALS socket control message.
type SCMCredentials interface {
	transport.CredentialsControlMessage

	// Credentials returns properly namespaced values for the sender's pid, uid
	// and gid.
	Credentials(t *kernel.Task) (kernel.ThreadID, auth.UID, auth.GID)
}

// LINT.IfChange

// SCMRights represents a SCM_RIGHTS socket control message.
type SCMRights interface {
	transport.RightsControlMessage

	// Files returns up to max RightsFiles.
	//
	// Returned files are consumed and ownership is transferred to the caller.
	// Subsequent calls to Files will return the next files.
	Files(ctx context.Context, max int) (rf RightsFiles, truncated bool)
}

// RightsFiles represents a SCM_RIGHTS socket control message. A reference is
// maintained for each fs.File and is release either when an FD is created or
// when the Release method is called.
//
// +stateify savable
type RightsFiles []*fs.File

// NewSCMRights creates a new SCM_RIGHTS socket control message representation
// using local sentry FDs.
func NewSCMRights(t *kernel.Task, fds []int32) (SCMRights, error) {
	files := make(RightsFiles, 0, len(fds))
	for _, fd := range fds {
		file := t.GetFile(fd)
		if file == nil {
			files.Release(t)
			return nil, linuxerr.EBADF
		}
		files = append(files, file)
	}
	return &files, nil
}

// Files implements SCMRights.Files.
func (fs *RightsFiles) Files(ctx context.Context, max int) (RightsFiles, bool) {
	n := max
	var trunc bool
	if l := len(*fs); n > l {
		n = l
	} else if n < l {
		trunc = true
	}
	rf := (*fs)[:n]
	*fs = (*fs)[n:]
	return rf, trunc
}

// Clone implements transport.RightsControlMessage.Clone.
func (fs *RightsFiles) Clone() transport.RightsControlMessage {
	nfs := append(RightsFiles(nil), *fs...)
	for _, nf := range nfs {
		nf.IncRef()
	}
	return &nfs
}

// Release implements transport.RightsControlMessage.Release.
func (fs *RightsFiles) Release(ctx context.Context) {
	for _, f := range *fs {
		f.DecRef(ctx)
	}
	*fs = nil
}

// rightsFDs gets up to the specified maximum number of FDs.
func rightsFDs(t *kernel.Task, rights SCMRights, cloexec bool, max int) ([]int32, bool) {
	files, trunc := rights.Files(t, max)
	fds := make([]int32, 0, len(files))
	for i := 0; i < max && len(files) > 0; i++ {
		fd, err := t.NewFDFrom(0, files[0], kernel.FDFlags{
			CloseOnExec: cloexec,
		})
		files[0].DecRef(t)
		files = files[1:]
		if err != nil {
			t.Warningf("Error inserting FD: %v", err)
			// This is what Linux does.
			break
		}

		fds = append(fds, int32(fd))
	}
	return fds, trunc
}

// PackRights packs as many FDs as will fit into the unused capacity of buf.
func PackRights(t *kernel.Task, rights SCMRights, cloexec bool, buf []byte, flags int) ([]byte, int) {
	maxFDs := (cap(buf) - len(buf) - linux.SizeOfControlMessageHeader) / 4
	// Linux does not return any FDs if none fit.
	if maxFDs <= 0 {
		flags |= linux.MSG_CTRUNC
		return buf, flags
	}
	fds, trunc := rightsFDs(t, rights, cloexec, maxFDs)
	if trunc {
		flags |= linux.MSG_CTRUNC
	}
	align := t.Arch().Width()
	return putCmsg(buf, flags, linux.SCM_RIGHTS, align, fds)
}

// LINT.ThenChange(./control_vfs2.go)

// scmCredentials represents an SCM_CREDENTIALS socket control message.
//
// +stateify savable
type scmCredentials struct {
	t    *kernel.Task
	kuid auth.KUID
	kgid auth.KGID
}

// NewSCMCredentials creates a new SCM_CREDENTIALS socket control message
// representation.
func NewSCMCredentials(t *kernel.Task, cred linux.ControlMessageCredentials) (SCMCredentials, error) {
	tcred := t.Credentials()
	kuid, err := tcred.UseUID(auth.UID(cred.UID))
	if err != nil {
		return nil, err
	}
	kgid, err := tcred.UseGID(auth.GID(cred.GID))
	if err != nil {
		return nil, err
	}
	if kernel.ThreadID(cred.PID) != t.ThreadGroup().ID() && !t.HasCapabilityIn(linux.CAP_SYS_ADMIN, t.PIDNamespace().UserNamespace()) {
		return nil, linuxerr.EPERM
	}
	return &scmCredentials{t, kuid, kgid}, nil
}

// Equals implements transport.CredentialsControlMessage.Equals.
func (c *scmCredentials) Equals(oc transport.CredentialsControlMessage) bool {
	if oc, _ := oc.(*scmCredentials); oc != nil && *c == *oc {
		return true
	}
	return false
}

func putUint64(buf []byte, n uint64) []byte {
	hostarch.ByteOrder.PutUint64(buf[len(buf):len(buf)+8], n)
	return buf[:len(buf)+8]
}

func putUint32(buf []byte, n uint32) []byte {
	hostarch.ByteOrder.PutUint32(buf[len(buf):len(buf)+4], n)
	return buf[:len(buf)+4]
}

// putCmsg writes a control message header and as much data as will fit into
// the unused capacity of a buffer.
func putCmsg(buf []byte, flags int, msgType uint32, align uint, data []int32) ([]byte, int) {
	space := bits.AlignDown(cap(buf)-len(buf), 4)

	// We can't write to space that doesn't exist, so if we are going to align
	// the available space, we must align down.
	//
	// align must be >= 4 and each data int32 is 4 bytes. The length of the
	// header is already aligned, so if we align to the width of the data there
	// are two cases:
	// 1. The aligned length is less than the length of the header. The
	// unaligned length was also less than the length of the header, so we
	// can't write anything.
	// 2. The aligned length is greater than or equal to the length of the
	// header. We can write the header plus zero or more bytes of data. We can't
	// write a partial int32, so the length of the message will be
	// min(aligned length, header + data).
	if space < linux.SizeOfControlMessageHeader {
		flags |= linux.MSG_CTRUNC
		return buf, flags
	}

	length := 4*len(data) + linux.SizeOfControlMessageHeader
	if length > space {
		length = space
	}
	buf = putUint64(buf, uint64(length))
	buf = putUint32(buf, linux.SOL_SOCKET)
	buf = putUint32(buf, msgType)
	for _, d := range data {
		if len(buf)+4 > cap(buf) {
			flags |= linux.MSG_CTRUNC
			break
		}
		buf = putUint32(buf, uint32(d))
	}
	return alignSlice(buf, align), flags
}

func putCmsgStruct(buf []byte, msgLevel, msgType uint32, align uint, data marshal.Marshallable) []byte {
	if cap(buf)-len(buf) < linux.SizeOfControlMessageHeader {
		return buf
	}
	ob := buf

	buf = putUint64(buf, uint64(linux.SizeOfControlMessageHeader))
	buf = putUint32(buf, msgLevel)
	buf = putUint32(buf, msgType)

	hdrBuf := buf
	buf = append(buf, marshal.Marshal(data)...)

	// If the control message data brought us over capacity, omit it.
	if cap(buf) != cap(ob) {
		return hdrBuf
	}

	// Update control message length to include data.
	putUint64(ob, uint64(len(buf)-len(ob)))

	return alignSlice(buf, align)
}

// Credentials implements SCMCredentials.Credentials.
func (c *scmCredentials) Credentials(t *kernel.Task) (kernel.ThreadID, auth.UID, auth.GID) {
	// "When a process's user and group IDs are passed over a UNIX domain
	// socket to a process in a different user namespace (see the description
	// of SCM_CREDENTIALS in unix(7)), they are translated into the
	// corresponding values as per the receiving process's user and group ID
	// mappings." - user_namespaces(7)
	pid := t.PIDNamespace().IDOfTask(c.t)
	uid := c.kuid.In(t.UserNamespace()).OrOverflow()
	gid := c.kgid.In(t.UserNamespace()).OrOverflow()

	return pid, uid, gid
}

// PackCredentials packs the credentials in the control message (or default
// credentials if none) into a buffer.
func PackCredentials(t *kernel.Task, creds SCMCredentials, buf []byte, flags int) ([]byte, int) {
	align := t.Arch().Width()

	// Default credentials if none are available.
	pid := kernel.ThreadID(0)
	uid := auth.UID(auth.NobodyKUID)
	gid := auth.GID(auth.NobodyKGID)

	if creds != nil {
		pid, uid, gid = creds.Credentials(t)
	}
	c := []int32{int32(pid), int32(uid), int32(gid)}
	return putCmsg(buf, flags, linux.SCM_CREDENTIALS, align, c)
}

// alignSlice extends a slice's length (up to the capacity) to align it.
func alignSlice(buf []byte, align uint) []byte {
	aligned := bits.AlignUp(len(buf), align)
	if aligned > cap(buf) {
		// Linux allows unaligned data if there isn't room for alignment.
		// Since there isn't room for alignment, there isn't room for any
		// additional messages either.
		return buf
	}
	return buf[:aligned]
}

// PackTimestamp packs a SO_TIMESTAMP socket control message.
func PackTimestamp(t *kernel.Task, timestamp int64, buf []byte) []byte {
	timestampP := linux.NsecToTimeval(timestamp)
	return putCmsgStruct(
		buf,
		linux.SOL_SOCKET,
		linux.SO_TIMESTAMP,
		t.Arch().Width(),
		&timestampP,
	)
}

// PackInq packs a TCP_INQ socket control message.
func PackInq(t *kernel.Task, inq int32, buf []byte) []byte {
	return putCmsgStruct(
		buf,
		linux.SOL_TCP,
		linux.TCP_INQ,
		t.Arch().Width(),
		primitive.AllocateInt32(inq),
	)
}

// PackTOS packs an IP_TOS socket control message.
func PackTOS(t *kernel.Task, tos uint8, buf []byte) []byte {
	return putCmsgStruct(
		buf,
		linux.SOL_IP,
		linux.IP_TOS,
		t.Arch().Width(),
		primitive.AllocateUint8(tos),
	)
}

// PackTClass packs an IPV6_TCLASS socket control message.
func PackTClass(t *kernel.Task, tClass uint32, buf []byte) []byte {
	return putCmsgStruct(
		buf,
		linux.SOL_IPV6,
		linux.IPV6_TCLASS,
		t.Arch().Width(),
		primitive.AllocateUint32(tClass),
	)
}

// PackIPPacketInfo packs an IP_PKTINFO socket control message.
func PackIPPacketInfo(t *kernel.Task, packetInfo *linux.ControlMessageIPPacketInfo, buf []byte) []byte {
	return putCmsgStruct(
		buf,
		linux.SOL_IP,
		linux.IP_PKTINFO,
		t.Arch().Width(),
		packetInfo,
	)
}

// PackOriginalDstAddress packs an IP_RECVORIGINALDSTADDR socket control message.
func PackOriginalDstAddress(t *kernel.Task, originalDstAddress linux.SockAddr, buf []byte) []byte {
	var level uint32
	var optType uint32
	switch originalDstAddress.(type) {
	case *linux.SockAddrInet:
		level = linux.SOL_IP
		optType = linux.IP_RECVORIGDSTADDR
	case *linux.SockAddrInet6:
		level = linux.SOL_IPV6
		optType = linux.IPV6_RECVORIGDSTADDR
	default:
		panic("invalid address type, must be an IP address for IP_RECVORIGINALDSTADDR cmsg")
	}
	return putCmsgStruct(
		buf, level, optType, t.Arch().Width(), originalDstAddress)
}

// PackSockExtendedErr packs an IP*_RECVERR socket control message.
func PackSockExtendedErr(t *kernel.Task, sockErr linux.SockErrCMsg, buf []byte) []byte {
	return putCmsgStruct(
		buf,
		sockErr.CMsgLevel(),
		sockErr.CMsgType(),
		t.Arch().Width(),
		sockErr,
	)
}

// PackControlMessages packs control messages into the given buffer.
//
// We skip control messages specific to Unix domain sockets.
//
// Note that some control messages may be truncated if they do not fit under
// the capacity of buf.
func PackControlMessages(t *kernel.Task, cmsgs socket.ControlMessages, buf []byte) []byte {
	if cmsgs.IP.HasTimestamp {
		buf = PackTimestamp(t, cmsgs.IP.Timestamp, buf)
	}

	if cmsgs.IP.HasInq {
		// In Linux, TCP_CM_INQ is added after SO_TIMESTAMP.
		buf = PackInq(t, cmsgs.IP.Inq, buf)
	}

	if cmsgs.IP.HasTOS {
		buf = PackTOS(t, cmsgs.IP.TOS, buf)
	}

	if cmsgs.IP.HasTClass {
		buf = PackTClass(t, cmsgs.IP.TClass, buf)
	}

	if cmsgs.IP.HasIPPacketInfo {
		buf = PackIPPacketInfo(t, &cmsgs.IP.PacketInfo, buf)
	}

	if cmsgs.IP.OriginalDstAddress != nil {
		buf = PackOriginalDstAddress(t, cmsgs.IP.OriginalDstAddress, buf)
	}

	if cmsgs.IP.SockErr != nil {
		buf = PackSockExtendedErr(t, cmsgs.IP.SockErr, buf)
	}

	return buf
}

// cmsgSpace is equivalent to CMSG_SPACE in Linux.
func cmsgSpace(t *kernel.Task, dataLen int) int {
	return linux.SizeOfControlMessageHeader + bits.AlignUp(dataLen, t.Arch().Width())
}

// CmsgsSpace returns the number of bytes needed to fit the control messages
// represented in cmsgs.
func CmsgsSpace(t *kernel.Task, cmsgs socket.ControlMessages) int {
	space := 0

	if cmsgs.IP.HasTimestamp {
		space += cmsgSpace(t, linux.SizeOfTimeval)
	}

	if cmsgs.IP.HasInq {
		space += cmsgSpace(t, linux.SizeOfControlMessageInq)
	}

	if cmsgs.IP.HasTOS {
		space += cmsgSpace(t, linux.SizeOfControlMessageTOS)
	}

	if cmsgs.IP.HasTClass {
		space += cmsgSpace(t, linux.SizeOfControlMessageTClass)
	}

	if cmsgs.IP.HasIPPacketInfo {
		space += cmsgSpace(t, linux.SizeOfControlMessageIPPacketInfo)
	}

	if cmsgs.IP.OriginalDstAddress != nil {
		space += cmsgSpace(t, cmsgs.IP.OriginalDstAddress.SizeBytes())
	}

	if cmsgs.IP.SockErr != nil {
		space += cmsgSpace(t, cmsgs.IP.SockErr.SizeBytes())
	}

	return space
}

// Parse parses a raw socket control message into portable objects.
func Parse(t *kernel.Task, socketOrEndpoint interface{}, buf []byte, width uint) (socket.ControlMessages, error) {
	var (
		cmsgs socket.ControlMessages
		fds   linux.ControlMessageRights
	)

	for i := 0; i < len(buf); {
		if i+linux.SizeOfControlMessageHeader > len(buf) {
			return cmsgs, linuxerr.EINVAL
		}

		var h linux.ControlMessageHeader
		h.UnmarshalUnsafe(buf[i : i+linux.SizeOfControlMessageHeader])

		if h.Length < uint64(linux.SizeOfControlMessageHeader) {
			return socket.ControlMessages{}, linuxerr.EINVAL
		}
		if h.Length > uint64(len(buf)-i) {
			return socket.ControlMessages{}, linuxerr.EINVAL
		}

		i += linux.SizeOfControlMessageHeader
		length := int(h.Length) - linux.SizeOfControlMessageHeader

		switch h.Level {
		case linux.SOL_SOCKET:
			switch h.Type {
			case linux.SCM_RIGHTS:
				rightsSize := bits.AlignDown(length, linux.SizeOfControlMessageRight)
				numRights := rightsSize / linux.SizeOfControlMessageRight

				if len(fds)+numRights > linux.SCM_MAX_FD {
					return socket.ControlMessages{}, linuxerr.EINVAL
				}

				for j := i; j < i+rightsSize; j += linux.SizeOfControlMessageRight {
					fds = append(fds, int32(hostarch.ByteOrder.Uint32(buf[j:j+linux.SizeOfControlMessageRight])))
				}

				i += bits.AlignUp(length, width)

			case linux.SCM_CREDENTIALS:
				if length < linux.SizeOfControlMessageCredentials {
					return socket.ControlMessages{}, linuxerr.EINVAL
				}

				var creds linux.ControlMessageCredentials
				creds.UnmarshalUnsafe(buf[i : i+linux.SizeOfControlMessageCredentials])
				scmCreds, err := NewSCMCredentials(t, creds)
				if err != nil {
					return socket.ControlMessages{}, err
				}
				cmsgs.Unix.Credentials = scmCreds
				i += bits.AlignUp(length, width)

			case linux.SO_TIMESTAMP:
				if length < linux.SizeOfTimeval {
					return socket.ControlMessages{}, linuxerr.EINVAL
				}
				var ts linux.Timeval
				ts.UnmarshalUnsafe(buf[i : i+linux.SizeOfTimeval])
				cmsgs.IP.Timestamp = ts.ToNsecCapped()
				cmsgs.IP.HasTimestamp = true
				i += bits.AlignUp(length, width)

			default:
				// Unknown message type.
				return socket.ControlMessages{}, linuxerr.EINVAL
			}
		case linux.SOL_IP:
			switch h.Type {
			case linux.IP_TOS:
				if length < linux.SizeOfControlMessageTOS {
					return socket.ControlMessages{}, linuxerr.EINVAL
				}
				cmsgs.IP.HasTOS = true
				var tos primitive.Uint8
				tos.UnmarshalUnsafe(buf[i : i+linux.SizeOfControlMessageTOS])
				cmsgs.IP.TOS = uint8(tos)
				i += bits.AlignUp(length, width)

			case linux.IP_PKTINFO:
				if length < linux.SizeOfControlMessageIPPacketInfo {
					return socket.ControlMessages{}, linuxerr.EINVAL
				}

				cmsgs.IP.HasIPPacketInfo = true
				var packetInfo linux.ControlMessageIPPacketInfo
				packetInfo.UnmarshalUnsafe(buf[i : i+linux.SizeOfControlMessageIPPacketInfo])

				cmsgs.IP.PacketInfo = packetInfo
				i += bits.AlignUp(length, width)

			case linux.IP_RECVORIGDSTADDR:
				var addr linux.SockAddrInet
				if length < addr.SizeBytes() {
					return socket.ControlMessages{}, linuxerr.EINVAL
				}
				addr.UnmarshalUnsafe(buf[i : i+addr.SizeBytes()])
				cmsgs.IP.OriginalDstAddress = &addr
				i += bits.AlignUp(length, width)

			case linux.IP_RECVERR:
				var errCmsg linux.SockErrCMsgIPv4
				if length < errCmsg.SizeBytes() {
					return socket.ControlMessages{}, linuxerr.EINVAL
				}

				errCmsg.UnmarshalBytes(buf[i : i+errCmsg.SizeBytes()])
				cmsgs.IP.SockErr = &errCmsg
				i += bits.AlignUp(length, width)

			default:
				return socket.ControlMessages{}, linuxerr.EINVAL
			}
		case linux.SOL_IPV6:
			switch h.Type {
			case linux.IPV6_TCLASS:
				if length < linux.SizeOfControlMessageTClass {
					return socket.ControlMessages{}, linuxerr.EINVAL
				}
				cmsgs.IP.HasTClass = true
				var tclass primitive.Uint32
				tclass.UnmarshalUnsafe(buf[i : i+linux.SizeOfControlMessageTClass])
				cmsgs.IP.TClass = uint32(tclass)
				i += bits.AlignUp(length, width)

			case linux.IPV6_RECVORIGDSTADDR:
				var addr linux.SockAddrInet6
				if length < addr.SizeBytes() {
					return socket.ControlMessages{}, linuxerr.EINVAL
				}
				addr.UnmarshalUnsafe(buf[i : i+addr.SizeBytes()])
				cmsgs.IP.OriginalDstAddress = &addr
				i += bits.AlignUp(length, width)

			case linux.IPV6_RECVERR:
				var errCmsg linux.SockErrCMsgIPv6
				if length < errCmsg.SizeBytes() {
					return socket.ControlMessages{}, linuxerr.EINVAL
				}

				errCmsg.UnmarshalBytes(buf[i : i+errCmsg.SizeBytes()])
				cmsgs.IP.SockErr = &errCmsg
				i += bits.AlignUp(length, width)

			default:
				return socket.ControlMessages{}, linuxerr.EINVAL
			}
		default:
			return socket.ControlMessages{}, linuxerr.EINVAL
		}
	}

	if cmsgs.Unix.Credentials == nil {
		cmsgs.Unix.Credentials = makeCreds(t, socketOrEndpoint)
	}

	if len(fds) > 0 {
		if kernel.VFS2Enabled {
			rights, err := NewSCMRightsVFS2(t, fds)
			if err != nil {
				return socket.ControlMessages{}, err
			}
			cmsgs.Unix.Rights = rights
		} else {
			rights, err := NewSCMRights(t, fds)
			if err != nil {
				return socket.ControlMessages{}, err
			}
			cmsgs.Unix.Rights = rights
		}
	}

	return cmsgs, nil
}

func makeCreds(t *kernel.Task, socketOrEndpoint interface{}) SCMCredentials {
	if t == nil || socketOrEndpoint == nil {
		return nil
	}
	if cr, ok := socketOrEndpoint.(transport.Credentialer); ok && (cr.Passcred() || cr.ConnectedPasscred()) {
		return MakeCreds(t)
	}
	return nil
}

// MakeCreds creates default SCMCredentials.
func MakeCreds(t *kernel.Task) SCMCredentials {
	if t == nil {
		return nil
	}
	tcred := t.Credentials()
	return &scmCredentials{t, tcred.EffectiveKUID, tcred.EffectiveKGID}
}

// LINT.IfChange

// New creates default control messages if needed.
func New(t *kernel.Task, socketOrEndpoint interface{}, rights SCMRights) transport.ControlMessages {
	return transport.ControlMessages{
		Credentials: makeCreds(t, socketOrEndpoint),
		Rights:      rights,
	}
}

// LINT.ThenChange(./control_vfs2.go)
