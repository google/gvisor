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

// Package strace implements the logic to print out the input and the return value
// of each traced syscall.
package strace

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/eventchannel"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	pb "gvisor.dev/gvisor/pkg/sentry/strace/strace_go_proto"
	slinux "gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// DefaultLogMaximumSize is the default LogMaximumSize.
const DefaultLogMaximumSize = 1024

// LogMaximumSize determines the maximum display size for data blobs (read,
// write, etc.).
var LogMaximumSize uint = DefaultLogMaximumSize

// EventMaximumSize determines the maximum size for data blobs (read, write,
// etc.) sent over the event channel. Default is 0 because most clients cannot
// do anything useful with binary text dump of byte array arguments.
var EventMaximumSize uint

// ItimerTypes are the possible itimer types.
var ItimerTypes = abi.ValueSet{
	linux.ITIMER_REAL:    "ITIMER_REAL",
	linux.ITIMER_VIRTUAL: "ITIMER_VIRTUAL",
	linux.ITIMER_PROF:    "ITIMER_PROF",
}

func iovecs(t *kernel.Task, addr usermem.Addr, iovcnt int, printContent bool, maxBytes uint64) string {
	if iovcnt < 0 || iovcnt > linux.UIO_MAXIOV {
		return fmt.Sprintf("%#x (error decoding iovecs: invalid iovcnt)", addr)
	}
	ars, err := t.CopyInIovecs(addr, iovcnt)
	if err != nil {
		return fmt.Sprintf("%#x (error decoding iovecs: %v)", addr, err)
	}

	var totalBytes uint64
	var truncated bool
	iovs := make([]string, iovcnt)
	for i := 0; !ars.IsEmpty(); i, ars = i+1, ars.Tail() {
		ar := ars.Head()
		if ar.Length() == 0 || !printContent {
			iovs[i] = fmt.Sprintf("{base=%#x, len=%d}", ar.Start, ar.Length())
			continue
		}

		size := uint64(ar.Length())
		if truncated || totalBytes+size > maxBytes {
			truncated = true
			size = maxBytes - totalBytes
		} else {
			totalBytes += uint64(ar.Length())
		}

		b := make([]byte, size)
		amt, err := t.CopyIn(ar.Start, b)
		if err != nil {
			iovs[i] = fmt.Sprintf("{base=%#x, len=%d, %q..., error decoding string: %v}", ar.Start, ar.Length(), b[:amt], err)
			continue
		}

		dot := ""
		if truncated {
			// Indicate truncation.
			dot = "..."
		}
		iovs[i] = fmt.Sprintf("{base=%#x, len=%d, %q%s}", ar.Start, ar.Length(), b[:amt], dot)
	}

	return fmt.Sprintf("%#x %s", addr, strings.Join(iovs, ", "))
}

func dump(t *kernel.Task, addr usermem.Addr, size uint, maximumBlobSize uint) string {
	origSize := size
	if size > maximumBlobSize {
		size = maximumBlobSize
	}
	if size == 0 {
		return ""
	}

	b := make([]byte, size)
	amt, err := t.CopyIn(addr, b)
	if err != nil {
		return fmt.Sprintf("%#x (error decoding string: %s)", addr, err)
	}

	dot := ""
	if uint(amt) < origSize {
		// ... if we truncated the dump.
		dot = "..."
	}

	return fmt.Sprintf("%#x %q%s", addr, b[:amt], dot)
}

func path(t *kernel.Task, addr usermem.Addr) string {
	path, err := t.CopyInString(addr, linux.PATH_MAX)
	if err != nil {
		return fmt.Sprintf("%#x (error decoding path: %s)", addr, err)
	}
	return fmt.Sprintf("%#x %s", addr, path)
}

func fd(t *kernel.Task, fd int32) string {
	root := t.FSContext().RootDirectory()
	if root != nil {
		defer root.DecRef()
	}

	if fd == linux.AT_FDCWD {
		wd := t.FSContext().WorkingDirectory()
		var name string
		if wd != nil {
			defer wd.DecRef()
			name, _ = wd.FullName(root)
		} else {
			name = "(unknown cwd)"
		}
		return fmt.Sprintf("AT_FDCWD %s", name)
	}

	file := t.GetFile(fd)
	if file == nil {
		// Cast FD to uint64 to avoid printing negative hex.
		return fmt.Sprintf("%#x (bad FD)", uint64(fd))
	}
	defer file.DecRef()

	name, _ := file.Dirent.FullName(root)
	return fmt.Sprintf("%#x %s", fd, name)
}

func fdpair(t *kernel.Task, addr usermem.Addr) string {
	var fds [2]int32
	_, err := t.CopyIn(addr, &fds)
	if err != nil {
		return fmt.Sprintf("%#x (error decoding fds: %s)", addr, err)
	}

	return fmt.Sprintf("%#x [%d %d]", addr, fds[0], fds[1])
}

func uname(t *kernel.Task, addr usermem.Addr) string {
	var u linux.UtsName
	if _, err := t.CopyIn(addr, &u); err != nil {
		return fmt.Sprintf("%#x (error decoding utsname: %s)", addr, err)
	}

	return fmt.Sprintf("%#x %s", addr, u)
}

func utimensTimespec(t *kernel.Task, addr usermem.Addr) string {
	if addr == 0 {
		return "null"
	}

	var tim linux.Timespec
	if _, err := t.CopyIn(addr, &tim); err != nil {
		return fmt.Sprintf("%#x (error decoding timespec: %s)", addr, err)
	}

	var ns string
	switch tim.Nsec {
	case linux.UTIME_NOW:
		ns = "UTIME_NOW"
	case linux.UTIME_OMIT:
		ns = "UTIME_OMIT"
	default:
		ns = fmt.Sprintf("%v", tim.Nsec)
	}
	return fmt.Sprintf("%#x {sec=%v nsec=%s}", addr, tim.Sec, ns)
}

func timespec(t *kernel.Task, addr usermem.Addr) string {
	if addr == 0 {
		return "null"
	}

	var tim linux.Timespec
	if _, err := t.CopyIn(addr, &tim); err != nil {
		return fmt.Sprintf("%#x (error decoding timespec: %s)", addr, err)
	}
	return fmt.Sprintf("%#x {sec=%v nsec=%v}", addr, tim.Sec, tim.Nsec)
}

func timeval(t *kernel.Task, addr usermem.Addr) string {
	if addr == 0 {
		return "null"
	}

	var tim linux.Timeval
	if _, err := t.CopyIn(addr, &tim); err != nil {
		return fmt.Sprintf("%#x (error decoding timeval: %s)", addr, err)
	}

	return fmt.Sprintf("%#x {sec=%v usec=%v}", addr, tim.Sec, tim.Usec)
}

func utimbuf(t *kernel.Task, addr usermem.Addr) string {
	if addr == 0 {
		return "null"
	}

	var utim syscall.Utimbuf
	if _, err := t.CopyIn(addr, &utim); err != nil {
		return fmt.Sprintf("%#x (error decoding utimbuf: %s)", addr, err)
	}

	return fmt.Sprintf("%#x {actime=%v, modtime=%v}", addr, utim.Actime, utim.Modtime)
}

func stat(t *kernel.Task, addr usermem.Addr) string {
	if addr == 0 {
		return "null"
	}

	var stat linux.Stat
	if _, err := t.CopyIn(addr, &stat); err != nil {
		return fmt.Sprintf("%#x (error decoding stat: %s)", addr, err)
	}
	return fmt.Sprintf("%#x {dev=%d, ino=%d, mode=%s, nlink=%d, uid=%d, gid=%d, rdev=%d, size=%d, blksize=%d, blocks=%d, atime=%s, mtime=%s, ctime=%s}", addr, stat.Dev, stat.Ino, linux.FileMode(stat.Mode), stat.Nlink, stat.UID, stat.GID, stat.Rdev, stat.Size, stat.Blksize, stat.Blocks, time.Unix(stat.ATime.Sec, stat.ATime.Nsec), time.Unix(stat.MTime.Sec, stat.MTime.Nsec), time.Unix(stat.CTime.Sec, stat.CTime.Nsec))
}

func itimerval(t *kernel.Task, addr usermem.Addr) string {
	if addr == 0 {
		return "null"
	}

	interval := timeval(t, addr)
	value := timeval(t, addr+usermem.Addr(binary.Size(linux.Timeval{})))
	return fmt.Sprintf("%#x {interval=%s, value=%s}", addr, interval, value)
}

func itimerspec(t *kernel.Task, addr usermem.Addr) string {
	if addr == 0 {
		return "null"
	}

	interval := timespec(t, addr)
	value := timespec(t, addr+usermem.Addr(binary.Size(linux.Timespec{})))
	return fmt.Sprintf("%#x {interval=%s, value=%s}", addr, interval, value)
}

func stringVector(t *kernel.Task, addr usermem.Addr) string {
	vec, err := t.CopyInVector(addr, slinux.ExecMaxElemSize, slinux.ExecMaxTotalSize)
	if err != nil {
		return fmt.Sprintf("%#x {error copying vector: %v}", addr, err)
	}
	s := fmt.Sprintf("%#x [", addr)
	for i, v := range vec {
		if i != 0 {
			s += ", "
		}
		s += fmt.Sprintf("%q", v)
	}
	s += "]"
	return s
}

func rusage(t *kernel.Task, addr usermem.Addr) string {
	if addr == 0 {
		return "null"
	}

	var ru linux.Rusage
	if _, err := t.CopyIn(addr, &ru); err != nil {
		return fmt.Sprintf("%#x (error decoding rusage: %s)", addr, err)
	}
	return fmt.Sprintf("%#x %+v", addr, ru)
}

func capHeader(t *kernel.Task, addr usermem.Addr) string {
	if addr == 0 {
		return "null"
	}

	var hdr linux.CapUserHeader
	if _, err := t.CopyIn(addr, &hdr); err != nil {
		return fmt.Sprintf("%#x (error decoding header: %s)", addr, err)
	}

	var version string
	switch hdr.Version {
	case linux.LINUX_CAPABILITY_VERSION_1:
		version = "1"
	case linux.LINUX_CAPABILITY_VERSION_2:
		version = "2"
	case linux.LINUX_CAPABILITY_VERSION_3:
		version = "3"
	default:
		version = strconv.FormatUint(uint64(hdr.Version), 16)
	}

	return fmt.Sprintf("%#x {Version: %s, Pid: %d}", addr, version, hdr.Pid)
}

func capData(t *kernel.Task, hdrAddr, dataAddr usermem.Addr) string {
	if dataAddr == 0 {
		return "null"
	}

	var hdr linux.CapUserHeader
	if _, err := t.CopyIn(hdrAddr, &hdr); err != nil {
		return fmt.Sprintf("%#x (error decoding header: %v)", dataAddr, err)
	}

	var p, i, e uint64

	switch hdr.Version {
	case linux.LINUX_CAPABILITY_VERSION_1:
		var data linux.CapUserData
		if _, err := t.CopyIn(dataAddr, &data); err != nil {
			return fmt.Sprintf("%#x (error decoding data: %v)", dataAddr, err)
		}
		p = uint64(data.Permitted)
		i = uint64(data.Inheritable)
		e = uint64(data.Effective)
	case linux.LINUX_CAPABILITY_VERSION_2, linux.LINUX_CAPABILITY_VERSION_3:
		var data [2]linux.CapUserData
		if _, err := t.CopyIn(dataAddr, &data); err != nil {
			return fmt.Sprintf("%#x (error decoding data: %v)", dataAddr, err)
		}
		p = uint64(data[0].Permitted) | (uint64(data[1].Permitted) << 32)
		i = uint64(data[0].Inheritable) | (uint64(data[1].Inheritable) << 32)
		e = uint64(data[0].Effective) | (uint64(data[1].Effective) << 32)
	default:
		return fmt.Sprintf("%#x (unknown version %d)", dataAddr, hdr.Version)
	}

	return fmt.Sprintf("%#x {Permitted: %s, Inheritable: %s, Effective: %s}", dataAddr, CapabilityBitset.Parse(p), CapabilityBitset.Parse(i), CapabilityBitset.Parse(e))
}

// pre fills in the pre-execution arguments for a system call. If an argument
// cannot be interpreted before the system call is executed, then a hex value
// will be used. Note that a full output slice will always be provided, that is
// len(return) == len(args).
func (i *SyscallInfo) pre(t *kernel.Task, args arch.SyscallArguments, maximumBlobSize uint) []string {
	var output []string

	for arg := range args {
		if arg >= len(i.format) {
			break
		}
		switch i.format[arg] {
		case FD:
			output = append(output, fd(t, args[arg].Int()))
		case WriteBuffer:
			output = append(output, dump(t, args[arg].Pointer(), args[arg+1].SizeT(), maximumBlobSize))
		case WriteIOVec:
			output = append(output, iovecs(t, args[arg].Pointer(), int(args[arg+1].Int()), true /* content */, uint64(maximumBlobSize)))
		case IOVec:
			output = append(output, iovecs(t, args[arg].Pointer(), int(args[arg+1].Int()), false /* content */, uint64(maximumBlobSize)))
		case SendMsgHdr:
			output = append(output, msghdr(t, args[arg].Pointer(), true /* content */, uint64(maximumBlobSize)))
		case RecvMsgHdr:
			output = append(output, msghdr(t, args[arg].Pointer(), false /* content */, uint64(maximumBlobSize)))
		case Path:
			output = append(output, path(t, args[arg].Pointer()))
		case ExecveStringVector:
			output = append(output, stringVector(t, args[arg].Pointer()))
		case SockAddr:
			output = append(output, sockAddr(t, args[arg].Pointer(), uint32(args[arg+1].Uint64())))
		case SockLen:
			output = append(output, sockLenPointer(t, args[arg].Pointer()))
		case SockFamily:
			output = append(output, SocketFamily.Parse(uint64(args[arg].Int())))
		case SockType:
			output = append(output, sockType(args[arg].Int()))
		case SockProtocol:
			output = append(output, sockProtocol(args[arg-2].Int(), args[arg].Int()))
		case SockFlags:
			output = append(output, sockFlags(args[arg].Int()))
		case Timespec:
			output = append(output, timespec(t, args[arg].Pointer()))
		case UTimeTimespec:
			output = append(output, utimensTimespec(t, args[arg].Pointer()))
		case ItimerVal:
			output = append(output, itimerval(t, args[arg].Pointer()))
		case ItimerSpec:
			output = append(output, itimerspec(t, args[arg].Pointer()))
		case Timeval:
			output = append(output, timeval(t, args[arg].Pointer()))
		case Utimbuf:
			output = append(output, utimbuf(t, args[arg].Pointer()))
		case CloneFlags:
			output = append(output, CloneFlagSet.Parse(uint64(args[arg].Uint())))
		case OpenFlags:
			output = append(output, open(uint64(args[arg].Uint())))
		case Mode:
			output = append(output, linux.FileMode(args[arg].ModeT()).String())
		case FutexOp:
			output = append(output, futex(uint64(args[arg].Uint())))
		case PtraceRequest:
			output = append(output, PtraceRequestSet.Parse(args[arg].Uint64()))
		case ItimerType:
			output = append(output, ItimerTypes.Parse(uint64(args[arg].Int())))
		case Signal:
			output = append(output, signalNames.ParseDecimal(args[arg].Uint64()))
		case SignalMaskAction:
			output = append(output, signalMaskActions.Parse(uint64(args[arg].Int())))
		case SigSet:
			output = append(output, sigSet(t, args[arg].Pointer()))
		case SigAction:
			output = append(output, sigAction(t, args[arg].Pointer()))
		case CapHeader:
			output = append(output, capHeader(t, args[arg].Pointer()))
		case CapData:
			output = append(output, capData(t, args[arg-1].Pointer(), args[arg].Pointer()))
		case PollFDs:
			output = append(output, pollFDs(t, args[arg].Pointer(), uint(args[arg+1].Uint()), false))
		case SelectFDSet:
			output = append(output, fdSet(t, int(args[0].Int()), args[arg].Pointer()))
		case Oct:
			output = append(output, "0o"+strconv.FormatUint(args[arg].Uint64(), 8))
		case Hex:
			fallthrough
		default:
			output = append(output, "0x"+strconv.FormatUint(args[arg].Uint64(), 16))
		}
	}

	return output
}

// post fills in the post-execution arguments for a system call. This modifies
// the given output slice in place with arguments that may only be interpreted
// after the system call has been executed.
func (i *SyscallInfo) post(t *kernel.Task, args arch.SyscallArguments, rval uintptr, output []string, maximumBlobSize uint) {
	for arg := range output {
		if arg >= len(i.format) {
			break
		}
		switch i.format[arg] {
		case ReadBuffer:
			output[arg] = dump(t, args[arg].Pointer(), uint(rval), maximumBlobSize)
		case ReadIOVec:
			printLength := uint64(rval)
			if printLength > uint64(maximumBlobSize) {
				printLength = uint64(maximumBlobSize)
			}
			output[arg] = iovecs(t, args[arg].Pointer(), int(args[arg+1].Int()), true /* content */, printLength)
		case WriteIOVec, IOVec, WriteBuffer:
			// We already have a big blast from write.
			output[arg] = "..."
		case SendMsgHdr:
			output[arg] = msghdr(t, args[arg].Pointer(), false /* content */, uint64(maximumBlobSize))
		case RecvMsgHdr:
			output[arg] = msghdr(t, args[arg].Pointer(), true /* content */, uint64(maximumBlobSize))
		case PostPath:
			output[arg] = path(t, args[arg].Pointer())
		case PipeFDs:
			output[arg] = fdpair(t, args[arg].Pointer())
		case Uname:
			output[arg] = uname(t, args[arg].Pointer())
		case Stat:
			output[arg] = stat(t, args[arg].Pointer())
		case PostSockAddr:
			output[arg] = postSockAddr(t, args[arg].Pointer(), args[arg+1].Pointer())
		case SockLen:
			output[arg] = sockLenPointer(t, args[arg].Pointer())
		case PostTimespec:
			output[arg] = timespec(t, args[arg].Pointer())
		case PostItimerVal:
			output[arg] = itimerval(t, args[arg].Pointer())
		case PostItimerSpec:
			output[arg] = itimerspec(t, args[arg].Pointer())
		case Timeval:
			output[arg] = timeval(t, args[arg].Pointer())
		case Rusage:
			output[arg] = rusage(t, args[arg].Pointer())
		case PostSigSet:
			output[arg] = sigSet(t, args[arg].Pointer())
		case PostSigAction:
			output[arg] = sigAction(t, args[arg].Pointer())
		case PostCapData:
			output[arg] = capData(t, args[arg-1].Pointer(), args[arg].Pointer())
		case PollFDs:
			output[arg] = pollFDs(t, args[arg].Pointer(), uint(args[arg+1].Uint()), true)
		}
	}
}

// printEntry prints the given system call entry.
func (i *SyscallInfo) printEnter(t *kernel.Task, args arch.SyscallArguments) []string {
	output := i.pre(t, args, LogMaximumSize)

	switch len(output) {
	case 0:
		t.Infof("%s E %s()", t.Name(), i.name)
	case 1:
		t.Infof("%s E %s(%s)", t.Name(), i.name,
			output[0])
	case 2:
		t.Infof("%s E %s(%s, %s)", t.Name(), i.name,
			output[0], output[1])
	case 3:
		t.Infof("%s E %s(%s, %s, %s)", t.Name(), i.name,
			output[0], output[1], output[2])
	case 4:
		t.Infof("%s E %s(%s, %s, %s, %s)", t.Name(), i.name,
			output[0], output[1], output[2], output[3])
	case 5:
		t.Infof("%s E %s(%s, %s, %s, %s, %s)", t.Name(), i.name,
			output[0], output[1], output[2], output[3], output[4])
	case 6:
		t.Infof("%s E %s(%s, %s, %s, %s, %s, %s)", t.Name(), i.name,
			output[0], output[1], output[2], output[3], output[4], output[5])
	}

	return output
}

// printExit prints the given system call exit.
func (i *SyscallInfo) printExit(t *kernel.Task, elapsed time.Duration, output []string, args arch.SyscallArguments, retval uintptr, err error, errno int) {
	var rval string
	if err == nil {
		// Fill in the output after successful execution.
		i.post(t, args, retval, output, LogMaximumSize)
		rval = fmt.Sprintf("%#x (%v)", retval, elapsed)
	} else {
		rval = fmt.Sprintf("%#x errno=%d (%s) (%v)", retval, errno, err, elapsed)
	}

	switch len(output) {
	case 0:
		t.Infof("%s X %s() = %s", t.Name(), i.name,
			rval)
	case 1:
		t.Infof("%s X %s(%s) = %s", t.Name(), i.name,
			output[0], rval)
	case 2:
		t.Infof("%s X %s(%s, %s) = %s", t.Name(), i.name,
			output[0], output[1], rval)
	case 3:
		t.Infof("%s X %s(%s, %s, %s) = %s", t.Name(), i.name,
			output[0], output[1], output[2], rval)
	case 4:
		t.Infof("%s X %s(%s, %s, %s, %s) = %s", t.Name(), i.name,
			output[0], output[1], output[2], output[3], rval)
	case 5:
		t.Infof("%s X %s(%s, %s, %s, %s, %s) = %s", t.Name(), i.name,
			output[0], output[1], output[2], output[3], output[4], rval)
	case 6:
		t.Infof("%s X %s(%s, %s, %s, %s, %s, %s) = %s", t.Name(), i.name,
			output[0], output[1], output[2], output[3], output[4], output[5], rval)
	}
}

// sendEnter sends the syscall enter to event log.
func (i *SyscallInfo) sendEnter(t *kernel.Task, args arch.SyscallArguments) []string {
	output := i.pre(t, args, EventMaximumSize)

	event := pb.Strace{
		Process:  t.Name(),
		Function: i.name,
		Info: &pb.Strace_Enter{
			Enter: &pb.StraceEnter{},
		},
	}
	for _, arg := range output {
		event.Args = append(event.Args, arg)
	}
	eventchannel.Emit(&event)

	return output
}

// sendExit sends the syscall exit to event log.
func (i *SyscallInfo) sendExit(t *kernel.Task, elapsed time.Duration, output []string, args arch.SyscallArguments, rval uintptr, err error, errno int) {
	if err == nil {
		// Fill in the output after successful execution.
		i.post(t, args, rval, output, EventMaximumSize)
	}

	exit := &pb.StraceExit{
		Return:    fmt.Sprintf("%#x", rval),
		ElapsedNs: elapsed.Nanoseconds(),
	}
	if err != nil {
		exit.Error = err.Error()
		exit.ErrNo = int64(errno)
	}
	event := pb.Strace{
		Process:  t.Name(),
		Function: i.name,
		Info:     &pb.Strace_Exit{Exit: exit},
	}
	for _, arg := range output {
		event.Args = append(event.Args, arg)
	}
	eventchannel.Emit(&event)
}

type syscallContext struct {
	info        SyscallInfo
	args        arch.SyscallArguments
	start       time.Time
	logOutput   []string
	eventOutput []string
	flags       uint32
}

// SyscallEnter implements kernel.Stracer.SyscallEnter. It logs the syscall
// entry trace.
func (s SyscallMap) SyscallEnter(t *kernel.Task, sysno uintptr, args arch.SyscallArguments, flags uint32) interface{} {
	info, ok := s[sysno]
	if !ok {
		info = SyscallInfo{
			name:   fmt.Sprintf("sys_%d", sysno),
			format: defaultFormat,
		}
	}

	var output, eventOutput []string
	if bits.IsOn32(flags, kernel.StraceEnableLog) {
		output = info.printEnter(t, args)
	}
	if bits.IsOn32(flags, kernel.StraceEnableEvent) {
		eventOutput = info.sendEnter(t, args)
	}

	return &syscallContext{
		info:        info,
		args:        args,
		start:       time.Now(),
		logOutput:   output,
		eventOutput: eventOutput,
		flags:       flags,
	}
}

// SyscallExit implements kernel.Stracer.SyscallExit. It logs the syscall
// exit trace.
func (s SyscallMap) SyscallExit(context interface{}, t *kernel.Task, sysno, rval uintptr, err error) {
	errno := t.ExtractErrno(err, int(sysno))
	c := context.(*syscallContext)

	elapsed := time.Since(c.start)
	if bits.IsOn32(c.flags, kernel.StraceEnableLog) {
		c.info.printExit(t, elapsed, c.logOutput, c.args, rval, err, errno)
	}
	if bits.IsOn32(c.flags, kernel.StraceEnableEvent) {
		c.info.sendExit(t, elapsed, c.eventOutput, c.args, rval, err, errno)
	}
}

// ConvertToSysnoMap converts the names to a map keyed on the syscall number
// and value set to true.
//
// The map is in a convenient format to pass to SyscallFlagsTable.Enable().
func (s SyscallMap) ConvertToSysnoMap(syscalls []string) (map[uintptr]bool, error) {
	if syscalls == nil {
		// Sentinel: no list.
		return nil, nil
	}

	l := make(map[uintptr]bool)
	for _, sc := range syscalls {
		// Try to match this system call.
		sysno, ok := s.ConvertToSysno(sc)
		if !ok {
			return nil, fmt.Errorf("syscall %q not found", sc)
		}
		l[sysno] = true
	}

	// Success.
	return l, nil
}

// ConvertToSysno converts the name to system call number. Returns false
// if syscall with same name is not found.
func (s SyscallMap) ConvertToSysno(syscall string) (uintptr, bool) {
	for sysno, info := range s {
		if info.name != "" && info.name == syscall {
			return sysno, true
		}
	}
	return 0, false
}

// Name returns the syscall name.
func (s SyscallMap) Name(sysno uintptr) string {
	if info, ok := s[sysno]; ok {
		return info.name
	}
	return fmt.Sprintf("sys_%d", sysno)
}

// Initialize prepares all syscall tables for use by this package.
//
// N.B. This is not in an init function because we can't be sure all syscall
// tables are registered with the kernel when init runs.
//
// TODO(gvisor.dev/issue/155): remove kernel package dependencies from this
// package and have the kernel package self-initialize all syscall tables.
func Initialize() {
	for _, table := range kernel.SyscallTables() {
		// Is this known?
		sys, ok := Lookup(table.OS, table.Arch)
		if !ok {
			continue
		}

		table.Stracer = sys
	}
}

// SinkType defines where to send straces to.
type SinkType uint32

const (
	// SinkTypeLog sends straces to text log
	SinkTypeLog SinkType = 1 << iota

	// SinkTypeEvent sends strace to event log
	SinkTypeEvent
)

func convertToSyscallFlag(sinks SinkType) uint32 {
	ret := uint32(0)
	if bits.IsOn32(uint32(sinks), uint32(SinkTypeLog)) {
		ret |= kernel.StraceEnableLog
	}
	if bits.IsOn32(uint32(sinks), uint32(SinkTypeEvent)) {
		ret |= kernel.StraceEnableEvent
	}
	return ret
}

// Enable enables the syscalls in whitelist in all syscall tables.
//
// Preconditions: Initialize has been called.
func Enable(whitelist []string, sinks SinkType) error {
	flags := convertToSyscallFlag(sinks)
	for _, table := range kernel.SyscallTables() {
		// Is this known?
		sys, ok := Lookup(table.OS, table.Arch)
		if !ok {
			continue
		}

		// Convert to a set of system calls numbers.
		wl, err := sys.ConvertToSysnoMap(whitelist)
		if err != nil {
			return err
		}

		table.FeatureEnable.Enable(flags, wl, true)
	}

	// Done.
	return nil
}

// Disable will disable Strace for all system calls and missing syscalls.
//
// Preconditions: Initialize has been called.
func Disable(sinks SinkType) {
	flags := convertToSyscallFlag(sinks)
	for _, table := range kernel.SyscallTables() {
		// Strace will be disabled for all syscalls including missing.
		table.FeatureEnable.Enable(flags, nil, false)
	}
}

// EnableAll enables all syscalls in all syscall tables.
//
// Preconditions: Initialize has been called.
func EnableAll(sinks SinkType) {
	flags := convertToSyscallFlag(sinks)
	for _, table := range kernel.SyscallTables() {
		// Is this known?
		if _, ok := Lookup(table.OS, table.Arch); !ok {
			continue
		}

		table.FeatureEnable.EnableAll(flags)
	}
}

func init() {
	t, ok := Lookup(abi.Host, arch.Host)
	if ok {
		// Provide the native table as the lookup for seccomp
		// debugging. This is best-effort. This is provided this way to
		// avoid dependencies from seccomp to this package.
		seccomp.SyscallName = t.Name
	}
}
