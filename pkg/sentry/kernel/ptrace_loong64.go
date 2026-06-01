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

//go:build loong64
// +build loong64

package kernel

import (
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// ptraceArch implements arch-specific ptrace commands. LoongArch defines
// the NT_LOONGARCH_{CPUCFG,CSR,LSX,LASX,LBT} regsets but gVisor does not
// expose any of them to the tracee, so this returns EIO for every request
// (matching arm64).
func (t *Task) ptraceArch(target *Task, req int64, addr, data hostarch.Addr) error {
	return linuxerr.EIO
}
