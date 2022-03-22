// Copyright 2021 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func getFilePath(ctx context.Context, fd int32) string {
	t := kernel.TaskFromContext(ctx)

	fdt := t.FDTable()
	if fdt == nil {
		return "[err: no FD table]"
	}
	file, _ := fdt.GetVFS2(fd)
	if file == nil {
		return "[err: requires VFS2]"
	}
	defer file.DecRef(ctx)

	root := vfs.RootFromContext(ctx)
	defer root.DecRef(ctx)

	path, err := t.Kernel().VFS().PathnameWithDeleted(ctx, root, file.VirtualDentry())
	if err != nil {
		return fmt.Sprintf("[err: %v]", err)
	}
	return path
}

func PointOpen(ctx context.Context, _ seccheck.FieldSet, common *pb.Common, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Open{
		Common: common,
		Sysno:  uint64(info.Sysno),
		Fd:     linux.AT_FDCWD,
		Flags:  info.Args[1].Uint(),
		Mode:   uint32(info.Args[2].ModeT()),
	}
	addr := info.Args[0].Pointer()
	if addr > 0 {
		t := kernel.TaskFromContext(ctx)
		path, err := t.CopyInString(addr, linux.PATH_MAX)
		if err == nil {
			p.Pathname = path
		}
	}
	p.Exit = seccheck.NewExitMaybe(info)
	return p
}

func PointClose(ctx context.Context, fields seccheck.FieldSet, common *pb.Common, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Close{
		Common: common,
		Sysno:  uint64(info.Sysno),
		Fd:     int64(info.Args[0].Int()),
	}

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(ctx, int32(p.Fd))
	}

	p.Exit = seccheck.NewExitMaybe(info)
	return p
}

func PointRead(ctx context.Context, fields seccheck.FieldSet, common *pb.Common, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Read{
		Common: common,
		Sysno:  uint64(info.Sysno),
		Fd:     int64(info.Args[0].Int()),
		Count:  uint64(info.Args[2].SizeT()),
	}
	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(ctx, int32(p.Fd))
	}

	p.Exit = seccheck.NewExitMaybe(info)

	return p
}

func PointOpenat(ctx context.Context, fields seccheck.FieldSet, common *pb.Common, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Open{
		Common: common,
		Sysno:  uint64(info.Sysno),
		Fd:     int64(info.Args[0].Int()),
		Flags:  info.Args[2].Uint(),
	}

	addr := info.Args[1].Pointer()
	if addr > 0 {
		t := kernel.TaskFromContext(ctx)
		path, err := t.CopyInString(addr, linux.PATH_MAX)
		if err == nil {
			p.Pathname = path
		}
	}
	if p.Flags&linux.O_CREAT != 0 {
		p.Mode = uint32(info.Args[3].ModeT())
	}

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(ctx, int32(p.Fd))
	}

	p.Exit = seccheck.NewExitMaybe(info)

	return p
}

func PointCreat(ctx context.Context, fields seccheck.FieldSet, common *pb.Common, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Open{
		Common: common,
		Sysno:  uint64(info.Sysno),
		Fd:     linux.AT_FDCWD,
		Flags:  linux.O_WRONLY | linux.O_CREAT | linux.O_TRUNC,
		Mode:   uint32(info.Args[1].ModeT()),
	}

	addr := info.Args[0].Pointer()
	if addr > 0 {
		t := kernel.TaskFromContext(ctx)
		path, err := t.CopyInString(addr, linux.PATH_MAX)
		if err == nil {
			p.Pathname = path
		}
	}

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(ctx, int32(p.Fd))
	}

	p.Exit = seccheck.NewExitMaybe(info)

	return p
}

func PointConnect(ctx context.Context, fields seccheck.FieldSet, common *pb.Common, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Connect{
		Common: common,
		Sysno:  uint64(info.Sysno),
		Fd:     int64(info.Args[0].Int()),
	}

	addr := info.Args[1].Pointer()
	addrlen := info.Args[2].Uint()
	if addr > 0 {
		t := kernel.TaskFromContext(ctx)
		p.Address = make([]byte, addrlen)
		_, _ = t.CopyInBytes(addr, p.Address)
	}

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(ctx, int32(p.Fd))
	}

	p.Exit = seccheck.NewExitMaybe(info)

	return p
}

func PointExecve(ctx context.Context, fields seccheck.FieldSet, common *pb.Common, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Execve{
		Common: common,
		Sysno:  uint64(info.Sysno),
	}
	t := kernel.TaskFromContext(ctx)
	if pathname, err := t.CopyInString(info.Args[0].Pointer(), linux.PATH_MAX); err == nil {
		p.Pathname = pathname
	}
	if argvAddr := info.Args[1].Pointer(); argvAddr != 0 {
		if argv, err := t.CopyInVector(argvAddr, ExecMaxElemSize, ExecMaxTotalSize); err == nil {
			p.Argv = argv
		}
	}

	if fields.Local.Contains(seccheck.FieldExecveEnvv) {
		if envvAddr := info.Args[2].Pointer(); envvAddr != 0 {
			if envv, err := t.CopyInVector(envvAddr, ExecMaxElemSize, ExecMaxTotalSize); err == nil {
				p.Envv = envv
			}
		}
	}

	p.Exit = seccheck.NewExitMaybe(info)

	return p
}

func PointExecveat(ctx context.Context, fields seccheck.FieldSet, common *pb.Common, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Execve{
		Common: common,
		Sysno:  uint64(info.Sysno),
		Fd:     int64(info.Args[0].Int()),
		Flags:  info.Args[4].Uint(),
	}
	t := kernel.TaskFromContext(ctx)
	if pathname, err := t.CopyInString(info.Args[1].Pointer(), linux.PATH_MAX); err == nil {
		p.Pathname = pathname
	}
	if argvAddr := info.Args[2].Pointer(); argvAddr != 0 {
		if argv, err := t.CopyInVector(argvAddr, ExecMaxElemSize, ExecMaxTotalSize); err == nil {
			p.Argv = argv
		}
	}

	if fields.Local.Contains(seccheck.FieldExecveEnvv) {
		if envvAddr := info.Args[3].Pointer(); envvAddr != 0 {
			if envv, err := t.CopyInVector(envvAddr, ExecMaxElemSize, ExecMaxTotalSize); err == nil {
				p.Envv = envv
			}
		}
	}
	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(ctx, int32(p.Fd))
	}

	p.Exit = seccheck.NewExitMaybe(info)

	return p
}
