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
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
)

const maxInt = int(^uint(0) >> 1)

// SCMCredentials represents a SCM_CREDENTIALS socket control message.
type SCMCredentials interface {
	transport.CredentialsControlMessage

	// Credentials returns properly namespaced values for the sender's pid, uid
	// and gid.
	Credentials(t *kernel.Task) (kernel.ThreadID, auth.UID, auth.GID)
}

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
			files.Release()
			return nil, syserror.EBADF
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
func (fs *RightsFiles) Release() {
	for _, f := range *fs {
		f.DecRef()
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
		files[0].DecRef()
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
		return nil, syserror.EPERM
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
	usermem.ByteOrder.PutUint64(buf[len(buf):len(buf)+8], n)
	return buf[:len(buf)+8]
}

func putUint32(buf []byte, n uint32) []byte {
	usermem.ByteOrder.PutUint32(buf[len(buf):len(buf)+4], n)
	return buf[:len(buf)+4]
}

// putCmsg writes a control message header and as much data as will fit into
// the unused capacity of a buffer.
func putCmsg(buf []byte, flags int, msgType uint32, align uint, data []int32) ([]byte, int) {
	space := AlignDown(cap(buf)-len(buf), 4)

	// We can't write to space that doesn't exist, so if we are going to align
	// the available space, we must align down.
	//
	// align must be >= 4 and each data int32 is 4 bytes. The length of the
	// header is already aligned, so if we align to the with of the data there
	// are two cases:
	// 1. The aligned length is less than the length of the header. The
	// unaligned length was also less than the length of the header, so we
	// can't write anything.
	// 2. The aligned length is greater than or equal to the length of the
	// header. We can write the header plus zero or more datas. We can't write
	// a partial int32, so the length of the message will be
	// min(aligned length, header + datas).
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

func putCmsgStruct(buf []byte, msgType uint32, align uint, data interface{}) []byte {
	if cap(buf)-len(buf) < linux.SizeOfControlMessageHeader {
		return buf
	}
	ob := buf

	buf = putUint64(buf, uint64(linux.SizeOfControlMessageHeader))
	buf = putUint32(buf, linux.SOL_SOCKET)
	buf = putUint32(buf, msgType)

	hdrBuf := buf

	buf = binary.Marshal(buf, usermem.ByteOrder, data)

	// Check if we went over.
	if cap(buf) != cap(ob) {
		return hdrBuf
	}

	// Fix up length.
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

// AlignUp rounds a length up to an alignment. align must be a power of 2.
func AlignUp(length int, align uint) int {
	return (length + int(align) - 1) & ^(int(align) - 1)
}

// AlignDown rounds a down to an alignment. align must be a power of 2.
func AlignDown(length int, align uint) int {
	return length & ^(int(align) - 1)
}

// alignSlice extends a slice's length (up to the capacity) to align it.
func alignSlice(buf []byte, align uint) []byte {
	aligned := AlignUp(len(buf), align)
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
	return putCmsgStruct(
		buf,
		linux.SO_TIMESTAMP,
		t.Arch().Width(),
		linux.NsecToTimeval(timestamp),
	)
}

// Parse parses a raw socket control message into portable objects.
func Parse(t *kernel.Task, socketOrEndpoint interface{}, buf []byte) (transport.ControlMessages, error) {
	var (
		fds       linux.ControlMessageRights
		haveCreds bool
		creds     linux.ControlMessageCredentials
	)

	for i := 0; i < len(buf); {
		if i+linux.SizeOfControlMessageHeader > len(buf) {
			return transport.ControlMessages{}, syserror.EINVAL
		}

		var h linux.ControlMessageHeader
		binary.Unmarshal(buf[i:i+linux.SizeOfControlMessageHeader], usermem.ByteOrder, &h)

		if h.Length < uint64(linux.SizeOfControlMessageHeader) {
			return transport.ControlMessages{}, syserror.EINVAL
		}
		if h.Length > uint64(len(buf)-i) {
			return transport.ControlMessages{}, syserror.EINVAL
		}
		if h.Level != linux.SOL_SOCKET {
			return transport.ControlMessages{}, syserror.EINVAL
		}

		i += linux.SizeOfControlMessageHeader
		length := int(h.Length) - linux.SizeOfControlMessageHeader

		// The use of t.Arch().Width() is analogous to Linux's use of
		// sizeof(long) in CMSG_ALIGN.
		width := t.Arch().Width()

		switch h.Type {
		case linux.SCM_RIGHTS:
			rightsSize := AlignDown(length, linux.SizeOfControlMessageRight)
			numRights := rightsSize / linux.SizeOfControlMessageRight

			if len(fds)+numRights > linux.SCM_MAX_FD {
				return transport.ControlMessages{}, syserror.EINVAL
			}

			for j := i; j < i+rightsSize; j += linux.SizeOfControlMessageRight {
				fds = append(fds, int32(usermem.ByteOrder.Uint32(buf[j:j+linux.SizeOfControlMessageRight])))
			}

			i += AlignUp(length, width)

		case linux.SCM_CREDENTIALS:
			if length < linux.SizeOfControlMessageCredentials {
				return transport.ControlMessages{}, syserror.EINVAL
			}

			binary.Unmarshal(buf[i:i+linux.SizeOfControlMessageCredentials], usermem.ByteOrder, &creds)
			haveCreds = true
			i += AlignUp(length, width)

		default:
			// Unknown message type.
			return transport.ControlMessages{}, syserror.EINVAL
		}
	}

	var credentials SCMCredentials
	if haveCreds {
		var err error
		if credentials, err = NewSCMCredentials(t, creds); err != nil {
			return transport.ControlMessages{}, err
		}
	} else {
		credentials = makeCreds(t, socketOrEndpoint)
	}

	var rights SCMRights
	if len(fds) > 0 {
		var err error
		if rights, err = NewSCMRights(t, fds); err != nil {
			return transport.ControlMessages{}, err
		}
	}

	if credentials == nil && rights == nil {
		return transport.ControlMessages{}, nil
	}

	return transport.ControlMessages{Credentials: credentials, Rights: rights}, nil
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

// New creates default control messages if needed.
func New(t *kernel.Task, socketOrEndpoint interface{}, rights SCMRights) transport.ControlMessages {
	return transport.ControlMessages{
		Credentials: makeCreds(t, socketOrEndpoint),
		Rights:      rights,
	}
}
