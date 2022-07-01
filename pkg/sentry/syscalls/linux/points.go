// Copyright 2022 The gVisor Authors.
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

package linux

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

func newExitMaybe(info kernel.SyscallInfo) *pb.Exit {
	if !info.Exit {
		return nil
	}
	return &pb.Exit{
		Result:  int64(info.Rval),
		Errorno: int64(info.Errno),
	}
}

func getFilePath(t *kernel.Task, fd int32) string {
	if fd < 0 {
		return ""
	}
	fdt := t.FDTable()
	if fdt == nil {
		return "[err: no FD table]"
	}
	file, _ := fdt.GetVFS2(fd)
	if file == nil {
		return "[err: FD not found]"
	}
	defer file.DecRef(t)

	root := t.MountNamespaceVFS2().Root()
	path, err := t.Kernel().VFS().PathnameWithDeleted(t, root, file.VirtualDentry())
	if err != nil {
		return fmt.Sprintf("[err: %v]", err)
	}
	return path
}

// PointOpen converts open(2) syscall to proto.
func PointOpen(t *kernel.Task, _ seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Open{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Fd:          linux.AT_FDCWD,
		Flags:       info.Args[1].Uint(),
		Mode:        uint32(info.Args[2].ModeT()),
	}
	addr := info.Args[0].Pointer()
	if addr > 0 {
		path, err := t.CopyInString(addr, linux.PATH_MAX)
		if err == nil { // if NO error
			p.Pathname = path
		}
	}
	p.Exit = newExitMaybe(info)
	return p, pb.MessageType_MESSAGE_SYSCALL_OPEN
}

// PointOpenat converts openat(2) syscall to proto.
func PointOpenat(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Open{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Fd:          int64(info.Args[0].Int()),
		Flags:       info.Args[2].Uint(),
	}

	addr := info.Args[1].Pointer()
	if addr > 0 {
		path, err := t.CopyInString(addr, linux.PATH_MAX)
		if err == nil { // if NO error
			p.Pathname = path
		}
	}
	if p.Flags&linux.O_CREAT != 0 {
		p.Mode = uint32(info.Args[3].ModeT())
	}

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(t, int32(p.Fd))
	}

	p.Exit = newExitMaybe(info)

	return p, pb.MessageType_MESSAGE_SYSCALL_OPEN
}

// PointCreat converts creat(2) syscall to proto.
func PointCreat(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Open{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Fd:          linux.AT_FDCWD,
		Flags:       linux.O_WRONLY | linux.O_CREAT | linux.O_TRUNC,
		Mode:        uint32(info.Args[1].ModeT()),
	}

	addr := info.Args[0].Pointer()
	if addr > 0 {
		path, err := t.CopyInString(addr, linux.PATH_MAX)
		if err == nil { // if NO error
			p.Pathname = path
		}
	}

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(t, int32(p.Fd))
	}

	p.Exit = newExitMaybe(info)

	return p, pb.MessageType_MESSAGE_SYSCALL_OPEN
}

// PointClose converts close(2) syscall to proto.
func PointClose(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Close{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Fd:          int64(info.Args[0].Int()),
	}

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(t, int32(p.Fd))
	}

	p.Exit = newExitMaybe(info)
	return p, pb.MessageType_MESSAGE_SYSCALL_CLOSE
}

// PointRead converts read(2) syscall to proto.
func PointRead(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Read{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Fd:          int64(info.Args[0].Int()),
		Count:       uint64(info.Args[2].SizeT()),
	}
	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(t, int32(p.Fd))
	}

	p.Exit = newExitMaybe(info)

	return p, pb.MessageType_MESSAGE_SYSCALL_READ
}

// PointSocket converts socket(2) syscall to proto.
func PointSocket(_ *kernel.Task, _ seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Socket{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Domain:      info.Args[0].Int(),
		Type:        info.Args[1].Int(),
		Protocol:    info.Args[2].Int(),
	}

	p.Exit = newExitMaybe(info)

	return p, pb.MessageType_MESSAGE_SYSCALL_SOCKET
}

// PointConnect converts connect(2) syscall to proto.
func PointConnect(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Connect{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Fd:          int64(info.Args[0].Int()),
	}

	addr := info.Args[1].Pointer()
	addrlen := info.Args[2].Uint()
	p.Address, _ = CaptureAddress(t, addr, addrlen)

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(t, int32(p.Fd))
	}

	p.Exit = newExitMaybe(info)

	return p, pb.MessageType_MESSAGE_SYSCALL_CONNECT
}

// PointExecve converts execve(2) syscall to proto.
func PointExecve(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Execve{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
	}
	if pathname, err := t.CopyInString(info.Args[0].Pointer(), linux.PATH_MAX); err == nil { // if NO error
		p.Pathname = pathname
	}
	if argvAddr := info.Args[1].Pointer(); argvAddr != 0 {
		if argv, err := t.CopyInVector(argvAddr, ExecMaxElemSize, ExecMaxTotalSize); err == nil { // if NO error
			p.Argv = argv
		}
	}

	if fields.Local.Contains(seccheck.FieldSyscallExecveEnvv) {
		if envvAddr := info.Args[2].Pointer(); envvAddr != 0 {
			if envv, err := t.CopyInVector(envvAddr, ExecMaxElemSize, ExecMaxTotalSize); err == nil { // if NO error
				p.Envv = envv
			}
		}
	}

	p.Exit = newExitMaybe(info)

	return p, pb.MessageType_MESSAGE_SYSCALL_EXECVE
}

// PointExecveat converts execveat(2) syscall to proto.
func PointExecveat(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Execve{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Fd:          int64(info.Args[0].Int()),
		Flags:       info.Args[4].Uint(),
	}
	if pathname, err := t.CopyInString(info.Args[1].Pointer(), linux.PATH_MAX); err == nil { // if NO error
		p.Pathname = pathname
	}
	if argvAddr := info.Args[2].Pointer(); argvAddr != 0 {
		if argv, err := t.CopyInVector(argvAddr, ExecMaxElemSize, ExecMaxTotalSize); err == nil { // if NO error
			p.Argv = argv
		}
	}

	if fields.Local.Contains(seccheck.FieldSyscallExecveEnvv) {
		if envvAddr := info.Args[3].Pointer(); envvAddr != 0 {
			if envv, err := t.CopyInVector(envvAddr, ExecMaxElemSize, ExecMaxTotalSize); err == nil { // if NO error
				p.Envv = envv
			}
		}
	}
	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(t, int32(p.Fd))
	}

	p.Exit = newExitMaybe(info)

	return p, pb.MessageType_MESSAGE_SYSCALL_EXECVE
}

// pointChdirHelper converts chdir(2) and fchdir(2) syscall to proto.
func pointChdirHelper(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo, fd int64, path hostarch.Addr) (proto.Message, pb.MessageType) {
	p := &pb.Chdir{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Fd:          fd,
	}

	if path > 0 {
		pathname, err := t.CopyInString(path, linux.PATH_MAX)
		if err == nil { // if NO error
			p.Pathname = pathname
		}
	}

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(t, int32(p.Fd))
	}

	p.Exit = newExitMaybe(info)

	return p, pb.MessageType_MESSAGE_SYSCALL_CHDIR
}

// PointChdir calls pointChdirHelper to convert chdir(2) syscall to proto.
func PointChdir(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	path := info.Args[0].Pointer()
	return pointChdirHelper(t, fields, cxtData, info, linux.AT_FDCWD, path)
}

// PointFchdir calls pointChdirHelper to convert fchdir(2) syscall to proto.
func PointFchdir(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	fd := int64(info.Args[0].Int())
	path := info.Args[1].Pointer()
	return pointChdirHelper(t, fields, cxtData, info, fd, path)
}

// pointSetidHelper converts setuid(2) and setgid(2) syscall to proto.
func pointSetidHelper(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo, id uint32) (proto.Message, pb.MessageType) {
	p := &pb.Setid{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Id:          id,
	}

	p.Exit = newExitMaybe(info)

	return p, pb.MessageType_MESSAGE_SYSCALL_SETID
}

// PointSetuid calls pointSetidHelper to convert setuid(2) syscall to proto.
func PointSetuid(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	id := info.Args[0].Uint()
	return pointSetidHelper(t, fields, cxtData, info, id)
}

// PointSetgid calls pointSetidHelper to convert setgid(2) syscall to proto.
func PointSetgid(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	id := info.Args[0].Uint()
	return pointSetidHelper(t, fields, cxtData, info, id)
}

// PointSetsid calls pointSetidHelper to convert setsid(2) syscall to proto.
func PointSetsid(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	return pointSetidHelper(t, fields, cxtData, info, 0)
}

// pointSetresidHelper converts setresuid(2) and setresgid(2) syscall to proto.
func pointSetresidHelper(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Setresid{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Rgid:        info.Args[0].Uint(),
		Egid:        info.Args[1].Uint(),
		Sgid:        info.Args[2].Uint(),
	}

	p.Exit = newExitMaybe(info)

	return p, pb.MessageType_MESSAGE_SYSCALL_SETRESID
}

// PointSetresuid calls pointSetresidHelper to convert setresuid(2) syscall to proto.
func PointSetresuid(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	return pointSetresidHelper(t, fields, cxtData, info)
}

// PointSetresgid calls pointSetresidHelper to convert setresgid(2) syscall to proto.
func PointSetresgid(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	return pointSetresidHelper(t, fields, cxtData, info)
}

func rlimits(rlimit rlimit64) *pb.StructRlimit {
	limit := rlimit.toLimit()
	return &pb.StructRlimit{
		Cur: limit.Cur,
		Max: limit.Max,
	}
}

// PointPrlimit64 call converts prlimit64(2) syscall to proto.
func PointPrlimit64(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Prlimit{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Pid:         int32(info.Args[0].Int()),
		Resource:    info.Args[1].Int64(),
	}

	if newRlimitAddr := info.Args[2].Pointer(); newRlimitAddr != 0 {
		var nrl rlimit64
		if err := nrl.copyIn(t, newRlimitAddr); err == nil { // if NO error
			p.NewLimit = rlimits(nrl)
		}
	}

	if oldRlimitAddr := info.Args[3].Pointer(); oldRlimitAddr != 0 {
		var orl rlimit64
		if err := orl.copyIn(t, oldRlimitAddr); err == nil { // if NO error
			p.OldLimit = rlimits(orl)
		}
	}

	p.Exit = newExitMaybe(info)

	return p, pb.MessageType_MESSAGE_SYSCALL_PRLIMIT64
}

// pipeHelper converts pipe(2) and pipe2(2) syscall to proto.
func pipeHelper(t *kernel.Task, cxtData *pb.ContextData, info kernel.SyscallInfo, flags uint32) (proto.Message, pb.MessageType) {
	p := &pb.Pipe{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Flags:       flags,
	}
	if info.Exit {
		if pipeFDAddr := info.Args[0].Pointer(); pipeFDAddr != 0 {
			var pipeFDs [2]int32
			if _, err := primitive.CopyInt32SliceIn(t, pipeFDAddr, pipeFDs[:]); err == nil { // if NO error
				p.Reader = pipeFDs[0]
				p.Writer = pipeFDs[1]
			}
		}
	}

	p.Exit = newExitMaybe(info)
	return p, pb.MessageType_MESSAGE_SYSCALL_PIPE
}

// PointPipe calls pipeHelper to convert pipe(2) syscall to proto.
func PointPipe(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	return pipeHelper(t, cxtData, info, 0)
}

// PointPipe2 calls pipeHelper to convert pipe2(2) syscall to proto.
func PointPipe2(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	flags := info.Args[1].Uint()
	return pipeHelper(t, cxtData, info, flags)
}

// eventfdHelper converts eventfd(2) and eventfd2(2) syscall to proto.
func eventfdHelper(cxtData *pb.ContextData, info kernel.SyscallInfo, flags uint32) (proto.Message, pb.MessageType) {
	p := &pb.Eventfd{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Val:         int32(info.Args[0].Int()),
		Flags:       flags,
	}

	p.Exit = newExitMaybe(info)
	return p, pb.MessageType_MESSAGE_SYSCALL_EVENTFD
}

// PointEventfd calls pipeHelper to convert eventfd(2) syscall to proto.
func PointEventfd(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	return eventfdHelper(cxtData, info, 0)
}

// PointEventfd2 calls pipeHelper to convert eventfd2(2) syscall to proto.
func PointEventfd2(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	flags := info.Args[1].Uint()
	return eventfdHelper(cxtData, info, flags)
}

// PointFcntl converts fcntl(2) syscall to proto.
func PointFcntl(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Fcntl{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Fd:          info.Args[0].Int(),
		Cmd:         info.Args[1].Int(),
		Args:        info.Args[2].Int64(),
	}

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(t, int32(p.Fd))
	}

	p.Exit = newExitMaybe(info)
	return p, pb.MessageType_MESSAGE_SYSCALL_FCNTL
}

// pointDupHelper converts dup(2), dup2(2), and dup3(2) syscall to proto.
func pointDupHelper(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo, oldFD, newFD int32, flags uint32) (proto.Message, pb.MessageType) {
	p := &pb.Dup{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		OldFd:       oldFD,
		NewFd:       newFD,
		Flags:       flags,
	}

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(t, int32(p.OldFd))
	}

	p.Exit = newExitMaybe(info)
	return p, pb.MessageType_MESSAGE_SYSCALL_DUP
}

// PointDup calls pointDupHelper to convert dup(2) syscall to proto.
func PointDup(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	oldFD := info.Args[0].Int()
	return pointDupHelper(t, fields, cxtData, info, oldFD, 0, 0)
}

// PointDup2 calls pointDupHelper to convert dup2(2) syscall to proto.
func PointDup2(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	oldFD := info.Args[0].Int()
	newFD := info.Args[1].Int()
	return pointDupHelper(t, fields, cxtData, info, oldFD, newFD, 0)
}

// PointDup3 calls pointDupHelper to convert dup3(2) syscall to proto.
func PointDup3(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	oldFD := info.Args[0].Int()
	newFD := info.Args[1].Int()
	flags := info.Args[2].Uint()
	return pointDupHelper(t, fields, cxtData, info, oldFD, newFD, flags)
}

// signalfdHelper converts signalfd(2) and signalfd4(2) syscall to proto.
func signalfdHelper(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo, flags int32) (proto.Message, pb.MessageType) {
	p := &pb.Signalfd{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Fd:          info.Args[0].Int(),
		Flags:       flags,
	}
	sigset := info.Args[1].Pointer()
	sigsetsize := info.Args[2].SizeT()
	mask, err := CopyInSigSet(t, sigset, sigsetsize)
	if err == nil { // if NO error
		p.Sigset = uint64(mask)
		p.Sigset = uint64(mask)
	}

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(t, int32(p.Fd))
	}

	p.Exit = newExitMaybe(info)
	return p, pb.MessageType_MESSAGE_SYSCALL_SIGNALFD
}

// PointSignalfd calls signalfdHelper to convert signalfd(2) syscall to proto.
func PointSignalfd(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	return signalfdHelper(t, fields, cxtData, info, 0)
}

// PointSignalfd4 calls signalfdHelper to convert signalfd4(2) syscall to proto.
func PointSignalfd4(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	flags := info.Args[3].Int()
	return signalfdHelper(t, fields, cxtData, info, flags)
}

// PointChroot converts chroot(2) syscall to proto.
func PointChroot(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Chroot{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
	}
	if pathname, err := t.CopyInString(info.Args[0].Pointer(), linux.PATH_MAX); err == nil { // if NO error
		p.Pathname = pathname
	}
	p.Exit = newExitMaybe(info)
	return p, pb.MessageType_MESSAGE_SYSCALL_CHROOT
}

// PointClone converts clone(2) syscall to proto.
func PointClone(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Clone{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Flags:       info.Args[0].Uint64(),
		Stack:       uint64(info.Args[1].Pointer()),
		Tls:         uint64(info.Args[4].Pointer()),
	}
	var parTid kernel.ThreadID

	parentTidAddr := info.Args[2].Pointer()
	if _, err := parTid.CopyIn(t, parentTidAddr); err == nil { // if NO error
		p.NewTid = uint64(parTid)
	}

	p.Exit = newExitMaybe(info)
	return p, pb.MessageType_MESSAGE_SYSCALL_CLONE
}

// PointBind converts bind(2) syscall to proto.
func PointBind(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	p := &pb.Bind{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Fd:          info.Args[0].Int(),
	}
	addr := info.Args[1].Pointer()
	addrLen := info.Args[2].Uint()
	if address, err := CaptureAddress(t, addr, addrLen); err == nil { // if NO error
		p.Address = address
	}

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(t, int32(p.Fd))
	}

	p.Exit = newExitMaybe(info)
	return p, pb.MessageType_MESSAGE_SYSCALL_BIND
}

func acceptHelper(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo, flags int32) (proto.Message, pb.MessageType) {
	p := &pb.Accept{
		ContextData: cxtData,
		Sysno:       uint64(info.Sysno),
		Fd:          info.Args[0].Int(),
		Flags:       flags,
	}
	addr := info.Args[1].Pointer()
	if addrLenPointer := info.Args[2].Pointer(); addrLenPointer != 0 {
		var addrLen uint32
		if _, err := primitive.CopyUint32In(t, addrLenPointer, &addrLen); err == nil { // if NO error
			if address, err := CaptureAddress(t, addr, addrLen); err == nil { // if NO error
				p.Address = address
			}
		}
	}

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(t, int32(p.Fd))
	}

	p.Exit = newExitMaybe(info)
	return p, pb.MessageType_MESSAGE_SYSCALL_ACCEPT
}

// PointAccept converts accept(2) syscall to proto.
func PointAccept(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	return acceptHelper(t, fields, cxtData, info, 0)
}

// PointAccept4 converts accept4(2) syscall to proto.
func PointAccept4(t *kernel.Task, fields seccheck.FieldSet, cxtData *pb.ContextData, info kernel.SyscallInfo) (proto.Message, pb.MessageType) {
	flags := info.Args[3].Int()
	return acceptHelper(t, fields, cxtData, info, flags)
}
