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

//go:build amd64
// +build amd64

package sandbox

import (
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/hostcpu"
	"gvisor.dev/gvisor/runsc/config"
)

func getMSRSpecCtrl() (uint64, error) {
	const _MSR_IA32_SPEC_CTRL = 0x00000048 // Speculation Control

	cpu := hostcpu.GetCPU()
	fd, err := os.Open(fmt.Sprintf("/dev/cpu/%d/msr", cpu))
	if err != nil {
		return 0, err
	}
	defer fd.Close()
	buf := [8]byte{}
	if _, err := fd.ReadAt(buf[:], _MSR_IA32_SPEC_CTRL); err != nil {
		return 0, err
	}
	v := primitive.Uint64(0)
	v.UnmarshalBytes(buf[:])
	return uint64(v), nil
}

func archUpdateSandboxArgs(conf *config.Config, args []string) []string {
	if conf.Platform == "kvm" {
		if v, err := getMSRSpecCtrl(); err != nil {
			log.Debugf("Unable to get MSR_IA32_SPEC_CTRL: %v", err)
		} else {
			args = append(args, fmt.Sprintf("--host-msr-spec-ctrl=0x%x", v))
		}
	}
	return args
}
