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
		if err == nil {
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
		if err == nil {
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
		if err == nil {
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
	if addr > 0 {
		p.Address = make([]byte, addrlen)
		_, _ = t.CopyInBytes(addr, p.Address)
	}

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
	if pathname, err := t.CopyInString(info.Args[0].Pointer(), linux.PATH_MAX); err == nil {
		p.Pathname = pathname
	}
	if argvAddr := info.Args[1].Pointer(); argvAddr != 0 {
		if argv, err := t.CopyInVector(argvAddr, ExecMaxElemSize, ExecMaxTotalSize); err == nil {
			p.Argv = argv
		}
	}

	if fields.Local.Contains(seccheck.FieldSyscallExecveEnvv) {
		if envvAddr := info.Args[2].Pointer(); envvAddr != 0 {
			if envv, err := t.CopyInVector(envvAddr, ExecMaxElemSize, ExecMaxTotalSize); err == nil {
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
	if pathname, err := t.CopyInString(info.Args[1].Pointer(), linux.PATH_MAX); err == nil {
		p.Pathname = pathname
	}
	if argvAddr := info.Args[2].Pointer(); argvAddr != 0 {
		if argv, err := t.CopyInVector(argvAddr, ExecMaxElemSize, ExecMaxTotalSize); err == nil {
			p.Argv = argv
		}
	}

	if fields.Local.Contains(seccheck.FieldSyscallExecveEnvv) {
		if envvAddr := info.Args[3].Pointer(); envvAddr != 0 {
			if envv, err := t.CopyInVector(envvAddr, ExecMaxElemSize, ExecMaxTotalSize); err == nil {
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
