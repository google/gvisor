// Copyright 2023 The gVisor Authors.
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

//go:build amd64
// +build amd64

package sysmsg

import (
	_ "embed"
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
)

// SighandlerBlob contains the compiled code of the sysmsg signal handler.
//
//go:embed sighandler.built-in.amd64.bin
var SighandlerBlob []byte

// ArchState defines variables specific to the architecture being
// used.
type ArchState struct {
	xsaveMode         uint32
	fpLen             uint32
	fsgsbase          uint32
	threadContextSize uint32
	// amx is 1 if applications may use AMX.
	amx uint32
}

// The linux kernel does not allow using xsavec from userspace, so we are limited
// to xsaveopt.
// See arch/x86/kernel/fpu/xstate.c:validate_user_xstate_header for details.
const (
	fxsave = iota
	xsave
	xsaveopt
)

// Init initializes the arch specific state. If amx is true, applications may
// use AMX.
func (s *ArchState) Init(amx bool) {
	fs := cpuid.HostFeatureSet()

	fpLenUint, _ := fs.ExtendedStateSize()
	// fpLen is the FP state length of contexts without AMX state.
	s.fpLen = uint32(fpLenUint - fs.AMXExtendedStateSize())
	// Size each slot for the XSAVE area of all features in XCR0, even if AMX
	// is disabled, because the application can change
	// ThreadContext.XFeatures.
	s.threadContextSize = threadContextSize(fpLenUint + fpu.FP_XSTATE_MAGIC2_SIZE)
	if fs.UseXsaveopt() {
		s.xsaveMode = xsaveopt
	} else if fs.UseXsave() {
		s.xsaveMode = xsave
	} else {
		s.xsaveMode = fxsave
	}

	if fs.UseFSGSBASE() {
		s.fsgsbase = 1
	}
	if amx {
		s.amx = 1
	}
}

// FpLen returns the FP state length of contexts without AMX tile data state.
func (s *ArchState) FpLen() int {
	return int(s.fpLen)
}

func (s *ArchState) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "sysmsg.ArchState{")
	fmt.Fprintf(&b, " xsaveMode %d", s.xsaveMode)
	fmt.Fprintf(&b, " fsgsbase %d", s.fsgsbase)
	fmt.Fprintf(&b, " fpLen %d", s.fpLen)
	fmt.Fprintf(&b, " threadContextSize %d", s.threadContextSize)
	fmt.Fprintf(&b, " amx %d", s.amx)
	b.WriteString(" }")

	return b.String()
}
