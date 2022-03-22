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

package seccheck

import (
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

type SyscallType int

const (
	SyscallEnter SyscallType = iota
	SyscallExit
	SyscallRawEnter
	SyscallRawExit

	syscallTypesCount
)

const (
	syscallsMax   = 2000
	syscallPoints = syscallsMax * int(syscallTypesCount)
)

const (
	FieldSyscallPath Field = iota
)

const (
	FieldExecveEnvv = FieldSyscallPath + 1
)

func GetPointForSyscall(typ SyscallType, sysno uintptr) Point {
	return Point(sysno)*Point(syscallTypesCount) + Point(typ) + pointLengthBeforeSyscalls
}

func (s *State) SyscallEnabled(typ SyscallType, sysno uintptr) bool {
	return s.Enabled(GetPointForSyscall(typ, sysno))
}

type SyscallToProto func(context.Context, FieldSet, *pb.Common, SyscallInfo) proto.Message

type SyscallInfo struct {
	Enter bool
	Sysno uintptr
	Args  arch.SyscallArguments
	Rval  uintptr
	Errno int
}

func NewExitMaybe(info SyscallInfo) *pb.Exit {
	if info.Enter {
		return nil
	}
	return &pb.Exit{
		Result:  int64(info.Rval),
		Errorno: int64(info.Errno),
	}
}
