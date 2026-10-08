// Copyright 2026 The gVisor Authors.
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

package systrap

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
)

func TestTrapRestartArgs(t *testing.T) {
	const (
		stubStart = 0x0000_7ffe_8000_0000
		stubRIP   = stubStart + 0x1000
		guestRIP  = 0x0000_5555_0000_1000
	)
	trap := uint32(linux.SECCOMP_RET_TRAP)
	allow := uint32(linux.SECCOMP_RET_ALLOW)
	neg := func(code unix.Errno) uint64 { return uint64(-int64(code)) }
	type test struct {
		name string
		rip  uint64
		nr   int32
		arg0 uint64
		want uint32
	}
	var tests []test
	for _, code := range restartArgCodes {
		low := uint64(uint32(neg(code)))
		for _, upper := range []struct {
			name string
			arg0 uint64
			flag uint32
		}{
			{"zero upper", low, restartArgZeroExtended},
			{"all-ones upper", neg(code), 0},
			{"other upper", 0x0000_aaaa_0000_0000 | low, 0},
		} {
			tests = append(tests, test{
				name: fmt.Sprintf("guest %d %s", -int64(code), upper.name),
				rip:  guestRIP,
				nr:   unix.SYS_EVENTFD2,
				arg0: upper.arg0,
				want: trap | uint32(code) | upper.flag,
			})
		}
	}
	tests = append(tests, []test{
		{
			name: "guest -4",
			rip:  guestRIP,
			nr:   unix.SYS_EVENTFD2,
			arg0: neg(unix.EINTR),
			want: trap,
		},
		{
			name: "guest -513",
			rip:  guestRIP,
			nr:   unix.SYS_EVENTFD2,
			arg0: neg(ERESTARTNOINTR),
			want: trap,
		},
		{
			name: "stub rt_sigreturn",
			rip:  stubRIP,
			nr:   unix.SYS_RT_SIGRETURN,
			arg0: neg(ERESTARTSYS),
			want: allow,
		},
		{
			name: "stub sched_yield",
			rip:  stubRIP,
			nr:   unix.SYS_SCHED_YIELD,
			arg0: neg(ERESTARTSYS),
			want: allow,
		},
		{
			name: "guest lower high word",
			rip:  0x0000_7ffd_9000_0000,
			nr:   unix.SYS_RT_SIGRETURN,
			arg0: neg(ERESTARTSYS),
			want: trap | uint32(ERESTARTSYS),
		},
		{
			name: "guest same high word",
			rip:  0x0000_7ffe_7000_0000,
			nr:   unix.SYS_RT_SIGRETURN,
			arg0: neg(ERESTARTSYS),
			want: trap | uint32(ERESTARTSYS),
		},
		{
			name: "stub higher high word",
			rip:  0x0000_aaaa_0000_1000,
			nr:   unix.SYS_RT_SIGRETURN,
			arg0: neg(ERESTARTSYS),
			want: allow,
		},
	}...)

	p, err := bpf.Compile(sysmsgThreadRules(stubStart), false)
	if err != nil {
		t.Fatalf("bpf.Compile got error: %v", err)
	}
	buf := make([]byte, (&linux.SeccompData{}).SizeBytes())
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := linux.SeccompData{
				Nr:                 test.nr,
				Arch:               linux.AUDIT_ARCH_AARCH64,
				InstructionPointer: test.rip,
				Args:               [6]uint64{test.arg0},
			}
			got, err := bpf.Exec[bpf.NativeEndian](p, seccomp.DataAsBPFInput(&data, buf))
			if err != nil {
				t.Fatalf("bpf.Exec got error: %v", err)
			}
			if got != test.want {
				t.Errorf("got %v, want %v", linux.BPFAction(got), linux.BPFAction(test.want))
			}
		})
	}
}
