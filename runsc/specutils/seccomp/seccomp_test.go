// Copyright 2020 The gVisor Authors.
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

package seccomp

import (
	"fmt"
	"math"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// testInput creates an Input struct with given seccomp input values.
func testInput(arch uint32, syscallName string, args *[6]uint64) bpf.Input {
	syscallNo, err := lookupSyscallNo(arch, syscallName)
	if err != nil {
		// Assume tests set valid syscall names.
		panic(err)
	}

	if args == nil {
		argArray := [6]uint64{0, 0, 0, 0, 0, 0}
		args = &argArray
	}

	data := linux.SeccompData{
		Nr:   int32(syscallNo),
		Arch: arch,
		Args: *args,
	}
	return seccomp.DataAsBPFInput(&data, make([]byte, data.SizeBytes()))
}

// errnoRetPtr returns a pointer to errno, for use as an OCI errnoRet or
// defaultErrnoRet field.
func errnoRetPtr(errno uint) *uint {
	return &errno
}

// testCase holds a seccomp test case.
type testCase struct {
	name     string
	config   specs.LinuxSeccomp
	input    bpf.Input
	expected uint32
}

var (
	// seccompTests is a list of speccomp test cases.
	seccompTests = []testCase{
		{
			name: "default_allow",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_ALLOW),
		},
		{
			name: "default_deny",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.EPERM))),
		},
		{
			name: "deny_arch",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"getcwd",
						},
						Action: specs.ActErrno,
					},
				},
			},
			// Syscall matches but the arch is AUDIT_ARCH_X86 so the return
			// value is the bad arch action.
			input: seccomp.DataAsBPFInput(
				&linux.SeccompData{Nr: 183, Arch: 0x40000003},
				make([]byte, (&linux.SeccompData{}).SizeBytes()),
			),
			expected: uint32(linux.SECCOMP_RET_KILL_THREAD),
		},
		{
			name: "match_name_errno",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"getcwd",
							"chmod",
						},
						Action: specs.ActErrno,
					},
					{
						Names: []string{
							"write",
						},
						Action: specs.ActTrace,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "getcwd", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.EPERM))),
		},
		{
			name: "match_name_trace",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"getcwd",
							"chmod",
						},
						Action: specs.ActErrno,
					},
					{
						Names: []string{
							"write",
						},
						Action: specs.ActTrace,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "write", nil),
			expected: uint32(linux.SECCOMP_RET_TRACE.WithReturnCode(uint16(unix.EPERM))),
		},
		{
			name: "no_match_name_allow",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"getcwd",
							"chmod",
						},
						Action: specs.ActErrno,
					},
					{
						Names: []string{
							"write",
						},
						Action: specs.ActTrace,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "openat", nil),
			expected: uint32(linux.SECCOMP_RET_ALLOW),
		},
		{
			name: "simple_match_args",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index: 0,
								Value: unix.CLONE_FS,
								Op:    specs.OpEqualTo,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone", &[6]uint64{unix.CLONE_FS}),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.EPERM))),
		},
		{
			name: "match_args_or",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index: 0,
								Value: unix.CLONE_FS,
								Op:    specs.OpEqualTo,
							},
							{
								Index: 0,
								Value: unix.CLONE_VM,
								Op:    specs.OpEqualTo,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone", &[6]uint64{unix.CLONE_FS}),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.EPERM))),
		},
		{
			name: "match_args_and",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"getsockopt",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index: 1,
								Value: unix.SOL_SOCKET,
								Op:    specs.OpEqualTo,
							},
							{
								Index: 2,
								Value: unix.SO_PEERCRED,
								Op:    specs.OpEqualTo,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "getsockopt", &[6]uint64{0, unix.SOL_SOCKET, unix.SO_PEERCRED}),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.EPERM))),
		},
		{
			name: "no_match_args_and",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"getsockopt",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index: 1,
								Value: unix.SOL_SOCKET,
								Op:    specs.OpEqualTo,
							},
							{
								Index: 2,
								Value: unix.SO_PEERCRED,
								Op:    specs.OpEqualTo,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "getsockopt", &[6]uint64{0, unix.SOL_SOCKET}),
			expected: uint32(linux.SECCOMP_RET_ALLOW),
		},
		{
			name: "Simple args (no match)",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index: 0,
								Value: unix.CLONE_FS,
								Op:    specs.OpEqualTo,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone", &[6]uint64{unix.CLONE_VM}),
			expected: uint32(linux.SECCOMP_RET_ALLOW),
		},
		{
			name: "OpMaskedEqual (match)",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index:    0,
								Value:    unix.CLONE_FS,
								ValueTwo: unix.CLONE_FS,
								Op:       specs.OpMaskedEqual,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone", &[6]uint64{unix.CLONE_FS | unix.CLONE_VM}),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.EPERM))),
		},
		{
			name: "OpMaskedEqual (no match)",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index:    0,
								Value:    unix.CLONE_FS | unix.CLONE_VM,
								ValueTwo: unix.CLONE_FS | unix.CLONE_VM,
								Op:       specs.OpMaskedEqual,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone", &[6]uint64{unix.CLONE_FS}),
			expected: uint32(linux.SECCOMP_RET_ALLOW),
		},
		{
			name: "OpMaskedEqual (clone)",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone",
						},
						// This comes from the Docker default seccomp
						// profile for clone.
						Args: []specs.LinuxSeccompArg{
							{
								Index:    0,
								Value:    0x7e020000,
								ValueTwo: 0x0,
								Op:       specs.OpMaskedEqual,
							},
						},
						Action: specs.ActAllow,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone", &[6]uint64{0x50f00}),
			expected: uint32(linux.SECCOMP_RET_ALLOW),
		},
		{
			name: "default_errno_ret",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: errnoRetPtr(uint(unix.ENOSYS)),
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.ENOSYS))),
		},
		{
			// errnoRet: 0 is distinct from an unset errnoRet: it means
			// "return 0", not "use the EPERM default".
			name: "default_errno_ret_zero",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: errnoRetPtr(0),
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(0)),
		},
		{
			// defaultErrnoRet is meaningless for SCMP_ACT_ALLOW; applying it
			// anyway would panic in BPFAction.WithReturnCode.
			name: "default_errno_ret_ignored_for_allow",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActAllow,
				DefaultErrnoRet: errnoRetPtr(uint(unix.ENOSYS)),
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_ALLOW),
		},
		{
			// Likewise for SCMP_ACT_KILL.
			name: "default_errno_ret_ignored_for_kill",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActKill,
				DefaultErrnoRet: errnoRetPtr(uint(unix.ENOSYS)),
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_KILL_THREAD),
		},
		{
			// This is the glibc >= 2.34 clone3 fallback pattern: clone3 must
			// return ENOSYS (not EPERM) or glibc will not fall back to
			// clone(2). See gvisor.dev/issue/14688.
			name: "match_name_errno_ret",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"clone3"},
						Action:   specs.ActErrno,
						ErrnoRet: errnoRetPtr(uint(unix.ENOSYS)),
					},
					{
						// No ErrnoRet: must fall back to EPERM, not
						// whatever the other rule in this profile requested.
						Names:  []string{"getcwd"},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone3", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.ENOSYS))),
		},
		{
			// Same profile as match_name_errno_ret: proves errnoRet is
			// plumbed per rule (per RuleSet), not shared across the profile.
			name: "match_name_errno_ret_default_eperm",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"clone3"},
						Action:   specs.ActErrno,
						ErrnoRet: errnoRetPtr(uint(unix.ENOSYS)),
					},
					{
						Names:  []string{"getcwd"},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "getcwd", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.EPERM))),
		},
		{
			name: "match_name_errno_ret_zero",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"clone3"},
						Action:   specs.ActErrno,
						ErrnoRet: errnoRetPtr(0),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone3", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(0)),
		},
		{
			name: "match_name_trace_ret",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"write"},
						Action:   specs.ActTrace,
						ErrnoRet: errnoRetPtr(uint(unix.ENOSYS)),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "write", nil),
			expected: uint32(linux.SECCOMP_RET_TRACE.WithReturnCode(uint16(unix.ENOSYS))),
		},
		{
			// errnoRet is meaningless for SCMP_ACT_ALLOW; applying it anyway
			// would panic in BPFAction.WithReturnCode.
			name: "errno_ret_ignored_for_allow",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"getcwd"},
						Action:   specs.ActAllow,
						ErrnoRet: errnoRetPtr(uint(unix.ENOSYS)),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "getcwd", nil),
			expected: uint32(linux.SECCOMP_RET_ALLOW),
		},
		{
			// Likewise for SCMP_ACT_TRAP.
			name: "errno_ret_ignored_for_trap",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"getcwd"},
						Action:   specs.ActTrap,
						ErrnoRet: errnoRetPtr(uint(unix.ENOSYS)),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "getcwd", nil),
			expected: uint32(linux.SECCOMP_RET_TRAP),
		},
		{
			// defaultErrnoRet must not leak into a per-rule action that
			// doesn't set its own errnoRet.
			name: "default_errno_ret_does_not_leak_to_rules",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActAllow,
				DefaultErrnoRet: errnoRetPtr(uint(unix.ENOSYS)),
				Syscalls: []specs.LinuxSyscall{
					{
						Names:  []string{"getcwd"},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "getcwd", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.EPERM))),
		},
	}
)

// errnoRetOutOfRangeTests are OCI seccomp profiles with an errnoRet that
// does not fit in the 16-bit SECCOMP_RET_DATA field, which BuildProgram
// must reject rather than silently truncate.
var errnoRetOutOfRangeTests = []testCase{
	{
		name: "default",
		config: specs.LinuxSeccomp{
			DefaultAction:   specs.ActErrno,
			DefaultErrnoRet: errnoRetPtr(math.MaxUint16 + 1),
		},
	},
	{
		name: "rule",
		config: specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Syscalls: []specs.LinuxSyscall{
				{
					Names:    []string{"getcwd"},
					Action:   specs.ActErrno,
					ErrnoRet: errnoRetPtr(math.MaxUint16 + 1),
				},
			},
		},
	},
}

// TestErrnoRetOutOfRange checks that an errnoRet that does not fit in the
// 16-bit SECCOMP_RET_DATA field is rejected by BuildProgram rather than
// silently truncated, which would otherwise reinterpret the rule (e.g.
// errnoRet: 0x10000 truncates to 0, turning a deny rule into an allow rule).
func TestErrnoRetOutOfRange(t *testing.T) {
	for _, tc := range errnoRetOutOfRangeTests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildProgram(&tc.config); err == nil {
				t.Errorf("BuildProgram(%+v) succeeded, want error", tc.config)
			}
		})
	}
}

// TestRunscSeccomp generates seccomp programs from OCI config and executes
// them using runsc's library, comparing against expected results.
func TestRunscSeccomp(t *testing.T) {
	for _, tc := range seccompTests {
		t.Run(tc.name, func(t *testing.T) {
			runscProgram, err := BuildProgram(&tc.config)
			if err != nil {
				t.Fatalf("generating runsc BPF: %v", err)
			}

			if err := checkProgram(runscProgram, tc.input, tc.expected); err != nil {
				t.Fatalf("running runsc BPF: %v", err)
			}
		})
	}
}

// checkProgram runs the given program over the given input and checks the
// result against the expected output.
func checkProgram(p bpf.Program, in bpf.Input, expected uint32) error {
	result, err := bpf.Exec[bpf.NativeEndian](p, in)
	if err != nil {
		return err
	}

	if result != expected {
		// Include a decoded version of the program in output for debugging purposes.
		decoded, _ := bpf.DecodeProgram(p)
		return fmt.Errorf("Unexpected result: got: %d, expected: %d\nBPF Program\n%s", result, expected, decoded)
	}

	return nil
}
