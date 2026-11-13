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
	"math"
	"math/rand"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/sentry"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// auditArchI386 is AUDIT_ARCH_I386.
const auditArchI386 = 0x40000003

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
			// Syscall matches but the arch is AUDIT_ARCH_I386 so the return
			// value is the bad arch action.
			input: seccomp.DataAsBPFInput(
				&linux.SeccompData{Nr: 183, Arch: auditArchI386},
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
			name: "match_name_log",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"write",
						},
						Action: specs.ActLog,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "write", nil),
			expected: uint32(linux.SECCOMP_RET_LOG),
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
			name: "first_rule_wins",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls: []specs.LinuxSyscall{
					{Names: []string{"read"}, Action: specs.ActTrap},
					{Names: []string{"read"}, Action: specs.ActAllow},
				},
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(linux.SECCOMP_RET_TRAP),
		},
		{
			name: "args_rule_then_all_rule_args_match",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls: []specs.LinuxSyscall{
					{Names: []string{"personality"}, Action: specs.ActKill, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 8, Op: specs.OpEqualTo}}},
					{Names: []string{"personality"}, Action: specs.ActAllow},
				},
			},
			input:    testInput(nativeArchAuditNo, "personality", &[6]uint64{8}),
			expected: uint32(linux.SECCOMP_RET_KILL_THREAD),
		},
		{
			name: "args_rule_then_all_rule_args_no_match",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls: []specs.LinuxSyscall{
					{Names: []string{"personality"}, Action: specs.ActKill, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 8, Op: specs.OpEqualTo}}},
					{Names: []string{"personality"}, Action: specs.ActAllow},
				},
			},
			input:    testInput(nativeArchAuditNo, "personality", &[6]uint64{9}),
			expected: uint32(linux.SECCOMP_RET_ALLOW),
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

// TestErrnoRetOutOfRange checks that an errnoRet that does not fit in the
// 16-bit SECCOMP_RET_DATA field is rejected by BuildFilter rather than
// silently truncated, which would otherwise reinterpret the rule (e.g.
// errnoRet: 0x10000 truncates to 0, turning a deny rule into an allow rule).
func TestErrnoRetOutOfRange(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config specs.LinuxSeccomp
	}{
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildFilter(&tc.config); err == nil {
				t.Errorf("BuildFilter(%+v) succeeded, want error", tc.config)
			}
		})
	}
}

// TestRunscSeccomp generates seccomp filters from OCI config and executes
// them using runsc's library, comparing against expected results.
func TestRunscSeccomp(t *testing.T) {
	for _, tc := range seccompTests {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := BuildFilter(&tc.config)
			if err != nil {
				t.Fatalf("generating runsc filter: %v", err)
			}
			result, err := filter.Evaluate(tc.input)
			if err != nil {
				t.Fatalf("running runsc filter: %v", err)
			}
			if result != tc.expected {
				t.Fatalf("got %#x, want %#x\nFilter:\n%v", result, tc.expected, filter)
			}
		})
	}
}

// buildFullProgram builds a program that has all the syscalls of the config.
func buildFullProgram(t *testing.T, s *specs.LinuxSeccomp) bpf.Program {
	t.Helper()
	defaultAction, err := convertAction(s.DefaultAction, s.DefaultErrnoRet)
	if err != nil {
		t.Fatalf("converting default action: %v", err)
	}
	rules, err := convertRules(s)
	if err != nil {
		t.Fatalf("converting rules: %v", err)
	}
	program, err := buildProgram(rules, defaultAction, func(uintptr) bool { return true })
	if err != nil {
		t.Fatalf("building full program: %v", err)
	}
	return program
}

// orderingTests are configs where more than one rule applies to a syscall.
var orderingTests = []struct {
	name   string
	config specs.LinuxSeccomp

	// argDependent are the syscalls where the action depends on the
	// arguments.
	argDependent []string
}{
	{
		name: "args_then_all_same_action",
		config: specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"personality"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 8, Op: specs.OpEqualTo}}},
				{Names: []string{"personality", "read"}, Action: specs.ActAllow},
			},
		},
	},
	{
		name: "args_then_all_other_action",
		config: specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"personality"}, Action: specs.ActKill, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 8, Op: specs.OpEqualTo}}},
				{Names: []string{"personality", "read"}, Action: specs.ActAllow},
			},
		},
		argDependent: []string{"personality"},
	},
	{
		name: "all_then_args",
		config: specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"personality", "read"}, Action: specs.ActAllow},
				{Names: []string{"personality"}, Action: specs.ActKill, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 8, Op: specs.OpEqualTo}}},
			},
		},
	},
	{
		name: "all_then_all",
		config: specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"read"}, Action: specs.ActTrap},
				{Names: []string{"read", "write"}, Action: specs.ActAllow},
			},
		},
	},
	{
		name: "args_only_default_action",
		config: specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"clone"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 0x7e020000, Op: specs.OpMaskedEqual}}},
			},
		},
	},
	{
		name: "args_only_other_action",
		config: specs.LinuxSeccomp{
			DefaultAction:   specs.ActErrno,
			DefaultErrnoRet: errnoRetPtr(uint(unix.ENOSYS)),
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"clone"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 0x7e020000, Op: specs.OpMaskedEqual}}},
				{Names: []string{"socket"}, Action: specs.ActLog, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 16, Op: specs.OpNotEqual}, {Index: 2, Value: 9, Op: specs.OpLessThan}}},
				{Names: []string{"socket"}, Action: specs.ActTrace, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 40, Op: specs.OpGreaterEqual}}},
			},
		},
		argDependent: []string{"clone", "socket"},
	},
	{
		name: "args_args_all",
		config: specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"personality", "read"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 8, Op: specs.OpEqualTo}}},
				{Names: []string{"personality", "write"}, Action: specs.ActKill, Args: []specs.LinuxSeccompArg{{Index: 1, Value: 8, Op: specs.OpGreaterThan}}},
				{Names: []string{"personality", "read", "write"}, Action: specs.ActAllow},
			},
		},
		argDependent: []string{"personality", "write"},
	},
	{
		name: "same_index_args",
		config: specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"personality"}, Action: specs.ActErrno, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 8, Op: specs.OpEqualTo}, {Index: 0, Value: 16, Op: specs.OpEqualTo}}},
			},
		},
		argDependent: []string{"personality"},
	},
	{
		name: "args_args_same_action",
		config: specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"personality"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 8, Op: specs.OpEqualTo}}},
				{Names: []string{"personality"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 16, Op: specs.OpEqualTo}}},
			},
		},
		argDependent: []string{"personality"},
	},
	{
		name: "unknown_names",
		config: specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"not_a_syscall"}, Action: specs.ActKill},
				{Names: []string{"not_a_syscall", "read"}, Action: specs.ActAllow},
			},
		},
	},
	{
		name: "args_default_action_other_errno",
		config: specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"personality"}, Action: specs.ActErrno, ErrnoRet: errnoRetPtr(uint(unix.ENOSYS)), Args: []specs.LinuxSeccompArg{{Index: 0, Value: 8, Op: specs.OpEqualTo}}},
			},
		},
		argDependent: []string{"personality"},
	},
	{
		name: "args_differ_by_errno",
		config: specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"personality"}, Action: specs.ActErrno, ErrnoRet: errnoRetPtr(uint(unix.ENOSYS)), Args: []specs.LinuxSeccompArg{{Index: 0, Value: 8, Op: specs.OpEqualTo}}},
				// A name that is present twice has the same result as a name
				// that is present once.
				{Names: []string{"personality", "personality"}, Action: specs.ActErrno},
			},
		},
		argDependent: []string{"personality"},
	},
}

// TestFilterMatchesFullProgram checks that a filter gives the same results as
// a program that has all the syscalls of the config.
func TestFilterMatchesFullProgram(t *testing.T) {
	type config struct {
		name   string
		config specs.LinuxSeccomp
	}
	var configs []config
	for _, tc := range seccompTests {
		configs = append(configs, config{tc.name, tc.config})
	}
	for _, tc := range orderingTests {
		configs = append(configs, config{tc.name, tc.config})
	}
	for _, tc := range configs {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := BuildFilter(&tc.config)
			if err != nil {
				t.Fatalf("BuildFilter: %v", err)
			}
			full := buildFullProgram(t, &tc.config)

			// Use the values around each argument of the config, at all
			// argument indexes.
			values := []uint64{0, math.MaxUint64}
			for _, sc := range tc.config.Syscalls {
				for _, arg := range sc.Args {
					for _, v := range []uint64{arg.Value, arg.ValueTwo} {
						values = append(values, v-1, v, v+1)
					}
				}
			}
			sysnos := []int32{-1, sentry.MaxSyscallNum + 1, 0x40000000, math.MaxInt32}
			for sysno := int32(0); sysno <= sentry.MaxSyscallNum; sysno++ {
				sysnos = append(sysnos, sysno)
			}
			buf := make([]byte, (&linux.SeccompData{}).SizeBytes())
			for _, arch := range []uint32{linux.AUDIT_ARCH_X86_64, linux.AUDIT_ARCH_AARCH64, auditArchI386} {
				for _, sysno := range sysnos {
					for _, v := range values {
						data := linux.SeccompData{Nr: sysno, Arch: arch, Args: [6]uint64{v, v, v, v, v, v}}
						input := seccomp.DataAsBPFInput(&data, buf)
						got, err := filter.Evaluate(input)
						if err != nil {
							t.Fatalf("arch %#x syscall %d value %#x: filter: %v", arch, sysno, v, err)
						}
						want, err := bpf.Exec[bpf.NativeEndian](full, input)
						if err != nil {
							t.Fatalf("arch %#x syscall %d value %#x: full program: %v", arch, sysno, v, err)
						}
						if got != want {
							t.Fatalf("arch %#x syscall %d value %#x: filter returns %#x, full program returns %#x", arch, sysno, v, got, want)
						}
					}
				}
			}
		})
	}
}

// TestSyscallActionsFixed checks that the action of a syscall is fixed
// unless it depends on the arguments.
func TestSyscallActionsFixed(t *testing.T) {
	for _, tc := range orderingTests {
		t.Run(tc.name, func(t *testing.T) {
			defaultAction, err := convertAction(tc.config.DefaultAction, tc.config.DefaultErrnoRet)
			if err != nil {
				t.Fatalf("converting default action: %v", err)
			}
			rules, err := convertRules(&tc.config)
			if err != nil {
				t.Fatalf("converting rules: %v", err)
			}
			argDependent := make(map[uintptr]bool)
			for _, name := range tc.argDependent {
				sysno, err := lookupSyscallNo(nativeArchAuditNo, name)
				if err != nil {
					t.Fatalf("looking up %q: %v", name, err)
				}
				argDependent[uintptr(sysno)] = true
			}
			for sysno, sa := range syscallActions(rules, defaultAction.BPF(linux.SECCOMP_RET_KILL_PROCESS)) {
				if got, want := sa.fixed, !argDependent[sysno]; got != want {
					t.Errorf("syscall %d: got fixed = %t, want %t", sysno, got, want)
				}
			}

			// The filter has a fixed action for all the other syscalls, and
			// its program only has the syscalls with no fixed action.
			filter, err := buildFilter(rules, defaultAction)
			if err != nil {
				t.Fatalf("buildFilter: %v", err)
			}
			for sysno := uintptr(0); sysno <= sentry.MaxSyscallNum; sysno++ {
				if _, got := filter.FixedAction(int32(sysno), nativeArchAuditNo); got != !argDependent[sysno] {
					t.Errorf("syscall %d: got fixed action = %t, want %t", sysno, got, !argDependent[sysno])
				}
			}
			noRules, err := buildFilter(nil, defaultAction)
			if err != nil {
				t.Fatalf("buildFilter with no rules: %v", err)
			}
			got, empty := filter.ProgramLength(), noRules.ProgramLength()
			if len(argDependent) == 0 && got != empty {
				t.Errorf("program has %d instructions, want the %d of a program with no rules", got, empty)
			}
			if len(argDependent) > 0 && got <= empty {
				t.Errorf("program has %d instructions, want more than the %d of a program with no rules", got, empty)
			}
		})
	}
}

// TestSyscallAboveMaxSyscallNum checks that a syscall number that a filter
// cannot hold a fixed action for has the action of its rule.
func TestSyscallAboveMaxSyscallNum(t *testing.T) {
	const sysno = sentry.MaxSyscallNum + 1
	filter, err := buildFilter([]ociRule{{
		sysnos: []uintptr{sysno},
		rule:   seccomp.MatchAll{},
		action: allowAction,
	}}, errnoAction)
	if err != nil {
		t.Fatalf("buildFilter: %v", err)
	}
	data := linux.SeccompData{Nr: sysno, Arch: nativeArchAuditNo}
	got, err := filter.Evaluate(seccomp.DataAsBPFInput(&data, make([]byte, data.SizeBytes())))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if want := uint32(linux.SECCOMP_RET_ALLOW); got != want {
		t.Errorf("got %#x, want %#x", got, want)
	}
}

// TestRandomFilterMatchesFullProgram checks that filters for random configs
// give the same results as programs that have all the syscalls of the
// configs.
func TestRandomFilterMatchesFullProgram(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	names := []string{"read", "write", "personality", "clone", "not_a_syscall"}
	actions := []specs.LinuxSeccompAction{specs.ActKill, specs.ActTrap, specs.ActErrno, specs.ActTrace, specs.ActLog, specs.ActAllow}
	errnoRets := []*uint{nil, errnoRetPtr(0), errnoRetPtr(uint(unix.EPERM)), errnoRetPtr(uint(unix.ENOSYS))}
	ops := []specs.LinuxSeccompOperator{specs.OpEqualTo, specs.OpNotEqual, specs.OpGreaterThan, specs.OpGreaterEqual, specs.OpLessThan, specs.OpLessEqual, specs.OpMaskedEqual}
	values := []uint64{0, 1, 2, 3}
	sysnos := []int32{-1, sentry.MaxSyscallNum + 1}
	for _, name := range names[:len(names)-1] {
		sysno, err := lookupSyscallNo(nativeArchAuditNo, name)
		if err != nil {
			t.Fatalf("looking up %q: %v", name, err)
		}
		sysnos = append(sysnos, int32(sysno))
	}
	buf := make([]byte, (&linux.SeccompData{}).SizeBytes())

	for i := 0; i < 2000; i++ {
		config := specs.LinuxSeccomp{
			DefaultAction:   actions[rng.Intn(len(actions))],
			DefaultErrnoRet: errnoRets[rng.Intn(len(errnoRets))],
		}
		for range rng.Intn(6) {
			sc := specs.LinuxSyscall{
				Action:   actions[rng.Intn(len(actions))],
				ErrnoRet: errnoRets[rng.Intn(len(errnoRets))],
			}
			for range rng.Intn(4) {
				sc.Names = append(sc.Names, names[rng.Intn(len(names))])
			}
			for range rng.Intn(3) {
				sc.Args = append(sc.Args, specs.LinuxSeccompArg{
					Index:    uint(rng.Intn(2)),
					Value:    values[rng.Intn(len(values))],
					ValueTwo: values[rng.Intn(len(values))],
					Op:       ops[rng.Intn(len(ops))],
				})
			}
			config.Syscalls = append(config.Syscalls, sc)
		}

		filter, err := BuildFilter(&config)
		if err != nil {
			t.Fatalf("BuildFilter(%+v): %v", config, err)
		}
		full := buildFullProgram(t, &config)
		for _, sysno := range sysnos {
			for _, arg0 := range values {
				for _, arg1 := range values {
					data := linux.SeccompData{Nr: sysno, Arch: nativeArchAuditNo, Args: [6]uint64{arg0, arg1}}
					input := seccomp.DataAsBPFInput(&data, buf)
					got, err := filter.Evaluate(input)
					if err != nil {
						t.Fatalf("config %+v syscall %d args (%d, %d): filter: %v", config, sysno, arg0, arg1, err)
					}
					want, err := bpf.Exec[bpf.NativeEndian](full, input)
					if err != nil {
						t.Fatalf("config %+v syscall %d args (%d, %d): full program: %v", config, sysno, arg0, arg1, err)
					}
					if got != want {
						t.Fatalf("config %+v syscall %d args (%d, %d): filter returns %#x, full program returns %#x", config, sysno, arg0, arg1, got, want)
					}
				}
			}
		}
	}
}
