// Copyright 2018 Google Inc.
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

package gofer

import (
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
)

func utimes(ctx context.Context, file contextFile, ts fs.TimeSpec) error {
	if ts.ATimeOmit && ts.MTimeOmit {
		return nil
	}
	mask := p9.SetAttrMask{
		ATime:              !ts.ATimeOmit,
		ATimeNotSystemTime: !ts.ATimeSetSystemTime,
		MTime:              !ts.MTimeOmit,
		MTimeNotSystemTime: !ts.MTimeSetSystemTime,
	}
	as, ans := ts.ATime.Unix()
	ms, mns := ts.MTime.Unix()
	attr := p9.SetAttr{
		ATimeSeconds:     uint64(as),
		ATimeNanoSeconds: uint64(ans),
		MTimeSeconds:     uint64(ms),
		MTimeNanoSeconds: uint64(mns),
	}
	// 9p2000.L SetAttr: "If a time bit is set without the corresponding SET bit,
	// the current system time on the server is used instead of the value sent
	// in the request."
	return file.setAttr(ctx, mask, attr)
}

func openFlagsFromPerms(p fs.PermMask) (p9.OpenFlags, error) {
	switch {
	case p.Read && p.Write:
		return p9.ReadWrite, nil
	case p.Write:
		return p9.WriteOnly, nil
	case p.Read:
		return p9.ReadOnly, nil
	default:
		return 0, syscall.EINVAL
	}
}
