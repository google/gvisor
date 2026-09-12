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
	"strings"
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

func uintPtr(u uint) *uint {
	return &u
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
			name: "default_deny_custom_errno",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: uintPtr(uint(unix.ENOSYS)),
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.ENOSYS))),
		},
		{
			name: "default_deny_custom_errno_zero",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: uintPtr(0),
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(0)),
		},
		{
			name: "default_trace_custom_errno",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActTrace,
				DefaultErrnoRet: uintPtr(42),
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_TRACE.WithReturnCode(42)),
		},
		{
			// runc compatibility: errnoRet is ignored for actions that do not support DATA (e.g. ActAllow).
			name: "default_allow_with_errno_ret",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActAllow,
				DefaultErrnoRet: uintPtr(1),
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_ALLOW),
		},
		{
			// runc compatibility: errnoRet overflow is ignored for actions that do not support DATA.
			name: "default_allow_with_errno_ret_overflow",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActAllow,
				DefaultErrnoRet: uintPtr(0x10000),
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_ALLOW),
		},
		{
			// runc compatibility: errnoRet overflow is ignored for ActTrap.
			name: "default_trap_with_errno_ret_overflow",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActTrap,
				DefaultErrnoRet: uintPtr(math.MaxUint),
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_TRAP),
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
			// runc compatibility: per-rule errnoRet is ignored for ActAllow.
			name: "syscall_allow_with_errno_ret",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"read"},
						Action:   specs.ActAllow,
						ErrnoRet: uintPtr(0),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_ALLOW),
		},
		{
			// runc compatibility: per-rule errnoRet is ignored for ActKill.
			name: "syscall_kill_with_errno_ret",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"read"},
						Action:   specs.ActKill,
						ErrnoRet: uintPtr(1),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_KILL_THREAD),
		},
		{
			// runc compatibility: per-rule errnoRet overflow is ignored for ActKill.
			name: "syscall_kill_with_errno_ret_overflow",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"read"},
						Action:   specs.ActKill,
						ErrnoRet: uintPtr(0x10000),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_KILL_THREAD),
		},
		{
			name: "match_name_custom_errno",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone3",
						},
						Action:   specs.ActErrno,
						ErrnoRet: uintPtr(uint(unix.ENOSYS)),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone3", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.ENOSYS))),
		},
		{
			// Note: OCI runtime-spec defines errnoRet as uint. In Linux seccomp BPF ABI,
			// SECCOMP_RET_ERRNO | 0 is legal and returned as-is (not coerced to EPERM).
			name: "errno_ret_zero",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone3",
						},
						Action:   specs.ActErrno,
						ErrnoRet: uintPtr(0),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone3", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(0)),
		},
		{
			name: "errno_ret_signed_max",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone3",
						},
						Action:   specs.ActErrno,
						ErrnoRet: uintPtr(0x7fff),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone3", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(0x7fff)),
		},
		{
			// Verify that 0x8000 (high bit set) is accepted as unsigned 16-bit DATA,
			// rather than being rejected or treated as negative errno.
			name: "errno_ret_high_bit",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone3",
						},
						Action:   specs.ActErrno,
						ErrnoRet: uintPtr(0x8000),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone3", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(0x8000)),
		},
		{
			name: "errno_ret_max",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone3",
						},
						Action:   specs.ActErrno,
						ErrnoRet: uintPtr(0xffff),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone3", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(0xffff)),
		},
		{
			name: "default_errno_matched_allow",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: uintPtr(uint(unix.ENOSYS)),
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"read",
						},
						Action: specs.ActAllow,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_ALLOW),
		},
		{
			name: "default_errno_unmatched_syscall",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: uintPtr(uint(unix.ENOSYS)),
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"read",
						},
						Action: specs.ActAllow,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "write", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.ENOSYS))),
		},
		{
			name: "match_name_custom_trace",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"write",
						},
						Action:   specs.ActTrace,
						ErrnoRet: uintPtr(42),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "write", nil),
			expected: uint32(linux.SECCOMP_RET_TRACE.WithReturnCode(42)),
		},
		{
			name: "trace_errno_ret_zero",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"write",
						},
						Action:   specs.ActTrace,
						ErrnoRet: uintPtr(0),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "write", nil),
			expected: uint32(linux.SECCOMP_RET_TRACE.WithReturnCode(0)),
		},
		{
			name: "trace_errno_ret_max",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"write",
						},
						Action:   specs.ActTrace,
						ErrnoRet: uintPtr(0xffff),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "write", nil),
			expected: uint32(linux.SECCOMP_RET_TRACE.WithReturnCode(0xffff)),
		},
		{
			name: "syscall_without_errno_ret_defaults_to_eperm_even_with_default_errno_ret",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: uintPtr(uint(unix.ENOSYS)),
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"read",
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.EPERM))),
		},
		{
			name: "syscall_custom_errno_overrides_default_errno",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: uintPtr(uint(unix.ENOSYS)),
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"read",
						},
						Action:   specs.ActErrno,
						ErrnoRet: uintPtr(uint(unix.EAGAIN)),
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(unix.EAGAIN))),
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
	}
)

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

// TestInvalidErrnoRet verifies that BuildProgram returns an error when errnoRet
// exceeds the 16-bit range or when an unsupported action is supplied.
func TestInvalidErrnoRet(t *testing.T) {
	testCases := []struct {
		name              string
		config            specs.LinuxSeccomp
		expectedErrSubstr string
	}{
		{
			name: "default_errno_ret_overflow_errno",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: uintPtr(0x10000),
			},
			expectedErrSubstr: "exceeds maximum 16-bit value",
		},
		{
			name: "default_errno_ret_overflow_trace",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActTrace,
				DefaultErrnoRet: uintPtr(0x10000),
			},
			expectedErrSubstr: "exceeds maximum 16-bit value",
		},
		{
			name: "default_errno_ret_overflow_max_uint",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: uintPtr(math.MaxUint),
			},
			expectedErrSubstr: "exceeds maximum 16-bit value",
		},
		{
			name: "syscall_errno_ret_overflow_errno",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"read"},
						Action:   specs.ActErrno,
						ErrnoRet: uintPtr(0x10000),
					},
				},
			},
			expectedErrSubstr: "exceeds maximum 16-bit value",
		},
		{
			name: "syscall_errno_ret_overflow_trace",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"read"},
						Action:   specs.ActTrace,
						ErrnoRet: uintPtr(0x10000),
					},
				},
			},
			expectedErrSubstr: "exceeds maximum 16-bit value",
		},
		{
			name: "syscall_errno_ret_overflow_max_uint",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"read"},
						Action:   specs.ActTrace,
						ErrnoRet: uintPtr(math.MaxUint),
					},
				},
			},
			expectedErrSubstr: "exceeds maximum 16-bit value",
		},
		{
			name: "default_action_unsupported_log_no_errno",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.LinuxSeccompAction("SCMP_ACT_LOG"),
			},
			expectedErrSubstr: "invalid action",
		},
		{
			name: "default_action_unsupported_log_with_overflow",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.LinuxSeccompAction("SCMP_ACT_LOG"),
				DefaultErrnoRet: uintPtr(0x10000),
			},
			expectedErrSubstr: "invalid action",
		},
		{
			name: "default_errno_ret_on_unsupported_log",
			config: specs.LinuxSeccomp{
				DefaultAction:   specs.LinuxSeccompAction("SCMP_ACT_LOG"),
				DefaultErrnoRet: uintPtr(1),
			},
			expectedErrSubstr: "invalid action",
		},
		{
			name: "syscall_action_unsupported_kill_process",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:  []string{"read"},
						Action: specs.LinuxSeccompAction("SCMP_ACT_KILL_PROCESS"),
					},
				},
			},
			expectedErrSubstr: "invalid action",
		},
		{
			name: "syscall_errno_ret_on_unsupported_notify",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"read"},
						Action:   specs.LinuxSeccompAction("SCMP_ACT_NOTIFY"),
						ErrnoRet: uintPtr(1),
					},
				},
			},
			expectedErrSubstr: "invalid action",
		},
		{
			name: "syscall_action_error_wrapped",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"clone3"},
						Action:   specs.ActErrno,
						ErrnoRet: uintPtr(0x10000),
					},
				},
			},
			expectedErrSubstr: "seccomp syscall names [clone3] action \"SCMP_ACT_ERRNO\"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildProgram(&tc.config)
			if err == nil {
				t.Fatalf("BuildProgram(%+v) succeeded, expected error", tc.config)
			}
			if tc.expectedErrSubstr != "" && !strings.Contains(err.Error(), tc.expectedErrSubstr) {
				t.Errorf("BuildProgram error %q does not contain expected substring %q", err.Error(), tc.expectedErrSubstr)
			}
		})
	}
}

