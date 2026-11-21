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

package config

import (
	"fmt"
	"reflect"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
	"gvisor.dev/gvisor/pkg/sentry/platform/kvm"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap"
)

func TestIoctlFirstArgumentIsNonNegativeFD(t *testing.T) {
	for name, options := range map[string]Options{
		"default systrap": {
			Platform: (&systrap.Systrap{}).SeccompInfo(),
		},
		"default kvm": {
			Platform: (&kvm.KVM{}).SeccompInfo(),
		},
		"nvproxy default": {
			Platform:    (&systrap.Systrap{}).SeccompInfo(),
			NVProxy:     true,
			NVProxyCaps: nvconf.DefaultDriverCaps,
		},
		"nvproxy all": {
			Platform:    (&systrap.Systrap{}).SeccompInfo(),
			NVProxy:     true,
			NVProxyCaps: nvconf.ValidCapabilities,
		},
		"tpuproxy": {
			Platform: (&systrap.Systrap{}).SeccompInfo(),
			TPUProxy: true,
		},
		"host network": {
			Platform:    (&systrap.Systrap{}).SeccompInfo(),
			HostNetwork: true,
		},
		"host network with raw sockets": {
			Platform:              (&systrap.Systrap{}).SeccompInfo(),
			HostNetwork:           true,
			HostNetworkRawSockets: true,
		},
		"profiling": {
			Platform:      (&systrap.Systrap{}).SeccompInfo(),
			ProfileEnable: true,
		},
		"host filesystem": {
			Platform: (&systrap.Systrap{}).SeccompInfo(),
			HostFS:   HostFSReadWrite,
		},
	} {
		t.Run(name, func(t *testing.T) {
			rules, _ := Rules(options)
			if err := rules.ForSingleArgument(unix.SYS_IOCTL, 0, func(v seccomp.ValueMatcher) error {
				if v == nil {
					return fmt.Errorf("nil first argument")
				}
				if _, isNonNegativeFD := v.(seccomp.NonNegativeFD); !isNonNegativeFD {
					return fmt.Errorf("first argument should be NonNegativeFD")
				}
				return nil
			}); err != nil {
				t.Fatalf("cannot look up PerArg rules for ioctl system call: %v", err)
			}
		})
	}
}

// TestOptionsConfigKey verifies the behavior of `Options.ConfigKey`.
func TestOptionsConfigKey(t *testing.T) {
	// mutateFn mutates the value of a specific Options field.
	type mutateFn func(opt *Options)

	defaultOpt := Options{
		Platform:       (&systrap.Systrap{}).SeccompInfo(),
		VendorSyscalls: precompiledseccomp.VarSyscallNumbers{"test": 1000},
	}

	// Map of `Options` struct field names mapped to a function to mutate them.
	// This should only contain fields which influence the configuration;
	// calling the mutation function of these should change the value of
	// `Options.Key`.
	configFields := map[string]mutateFn{
		"Platform": func(opt *Options) {
			if defaultOpt.Platform.ConfigKey() == opt.Platform.ConfigKey() {
				opt.Platform = (&kvm.KVM{}).SeccompInfo()
			} else {
				opt.Platform = (&systrap.Systrap{}).SeccompInfo()
			}
		},
		"HostNetwork":           func(opt *Options) { opt.HostNetwork = !opt.HostNetwork },
		"HostNetworkRawSockets": func(opt *Options) { opt.HostNetworkRawSockets = !opt.HostNetworkRawSockets },
		"HostFS":                func(opt *Options) { opt.HostFS = (opt.HostFS + 1) % (HostFSReadWrite + 1) },
		"ProfileEnable":         func(opt *Options) { opt.ProfileEnable = !opt.ProfileEnable },
		"NVProxy":               func(opt *Options) { opt.NVProxy = !opt.NVProxy },
		"NVProxyCaps":           func(opt *Options) { opt.NVProxyCaps = ^opt.NVProxyCaps },
		"TPUProxy":              func(opt *Options) { opt.TPUProxy = !opt.TPUProxy },
		"RDMAProxy":             func(opt *Options) { opt.RDMAProxy = !opt.RDMAProxy },
		"CgoEnabled":            func(opt *Options) { opt.CgoEnabled = !opt.CgoEnabled },
		"PluginNetwork":         func(opt *Options) { opt.PluginNetwork = !opt.PluginNetwork },
		"VendorSyscalls": func(opt *Options) {
			if len(opt.VendorSyscalls) == 0 {
				opt.VendorSyscalls = precompiledseccomp.VarSyscallNumbers{"test": 1000}
			} else {
				opt.VendorSyscalls = nil
			}
		},
	}

	// Map of `Options` struct field names mapped to a function to mutate them.
	// This should only contain fields which are used as variables during
	// filter generation; calling the mutation function of these should *not*
	// change the value of `Options.Key`.
	var varsFields = map[string]mutateFn{
		"ControllerFD": func(opt *Options) { opt.ControllerFD++ },
		"ProcSelfFD":   func(opt *Options) { opt.ProcSelfFD++ },
		"VendorSyscalls": func(opt *Options) {
			sn := make(precompiledseccomp.VarSyscallNumbers, len(opt.VendorSyscalls))
			for name, sysno := range opt.VendorSyscalls {
				sn[name] = sysno + 1
			}
			opt.VendorSyscalls = sn
		},
	}

	t.Run("fields are exhaustive", func(t *testing.T) {
		for i := 0; i < reflect.ValueOf(defaultOpt).NumField(); i++ {
			f := reflect.TypeOf(defaultOpt).Field(i)
			found := false
			for name := range configFields {
				if f.Name == name {
					found = true
					break
				}
			}
			for name := range varsFields {
				if f.Name == name {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("field `Options.%s` is not known to TestOptionsKey; please add it", f.Name)
			}
		}
	})

	t.Run("mutating config fields causes ConfigKey to change", func(t *testing.T) {
		opt := defaultOpt // Make a copy, as we're about to mutate it.
		key := opt.ConfigKey()
		for name, mutateFn := range configFields {
			mutateFn(&opt)
			newKey := opt.ConfigKey()
			if key == newKey {
				t.Fatalf("mutating config field %q did not cause the ConfigKey to change: %q", name, key)
			}
			key = newKey
		}
	})

	t.Run("mutating vars fields does not cause ConfigKey to change", func(t *testing.T) {
		opt := defaultOpt // Make a copy, as we're about to mutate it.
		key := opt.ConfigKey()
		for name, mutateFn := range varsFields {
			mutateFn(&opt)
			if newKey := opt.ConfigKey(); key != newKey {
				t.Fatalf("mutating var field %q caused the ConfigKey to change: %q -> %q", name, key, newKey)
			}
		}
	})
}

// TestPrecompiledProgramsDeterministic verifies that compiling programs
// concurrently produces the same output as compiling them one at a time.
func TestPrecompiledProgramsDeterministic(t *testing.T) {
	// Make sure that compilations run in parallel even with few CPUs.
	const minProcs = 8
	if runtime.GOMAXPROCS(0) < minProcs {
		defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(minProcs))
	}
	serial, err := precompiledPrograms(1)
	if err != nil {
		t.Fatalf("precompiledPrograms(1) failed: %v", err)
	}
	concurrent, err := PrecompiledPrograms()
	if err != nil {
		t.Fatalf("PrecompiledPrograms() failed: %v", err)
	}
	if len(serial) != len(concurrent) {
		t.Fatalf("got %d programs when compiling concurrently, want %d", len(concurrent), len(serial))
	}
	for i := range serial {
		if !reflect.DeepEqual(serial[i], concurrent[i]) {
			t.Errorf("program %d (%q) differs between serial and concurrent compilation (concurrent name: %q)", i, serial[i].Name, concurrent[i].Name)
		}
	}
}

// compileFilter returns the compiled seccomp program for opt.
func compileFilter(t *testing.T, opt Options) bpf.Program {
	t.Helper()
	rules, denyRules := Rules(opt)
	program := seccomp.Program{
		RuleSets: []seccomp.RuleSet{
			{Rules: denyRules},
			{Rules: rules, Action: seccomp.Allow},
		},
		Options: seccomp.ProgramOptions{DefaultAction: seccomp.KillProcess},
	}
	insns, _, err := program.Build()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := bpf.Compile(insns, true /* optimize */)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// filterAllows returns true if the compiled seccomp program allows the
// syscall.
func filterAllows(t *testing.T, compiled bpf.Program, sysno uintptr, args [6]uint64) bool {
	t.Helper()
	data := linux.SeccompData{Nr: int32(sysno), Arch: seccomp.LINUX_AUDIT_ARCH, Args: args}
	got, err := bpf.Exec[bpf.NativeEndian](compiled, seccomp.DataAsBPFInput(&data, make([]byte, data.SizeBytes())))
	if err != nil {
		t.Fatalf("syscall %d with args %#x: %v", sysno, args, err)
	}
	return got == uint32(linux.SECCOMP_RET_ALLOW)
}

func TestMknodat(t *testing.T) {
	atFDCWD32 := int32(linux.AT_FDCWD)
	atFDCWD64 := int64(linux.AT_FDCWD)
	for _, hostFS := range []HostFSAccess{HostFSNone, HostFSReadOnly, HostFSReadWrite} {
		compiled := compileFilter(t, Options{
			HostFS:   hostFS,
			Platform: (&systrap.Systrap{}).SeccompInfo(),
		})
		canCreate := hostFS == HostFSReadWrite
		for _, tc := range []struct {
			name    string
			args    [6]uint64
			allowed bool
		}{
			{"regular file", [6]uint64{10, 0x1000, unix.S_IFREG | 0o644, 0}, canCreate},
			{"regular file setuid sticky", [6]uint64{0, 0x1000, unix.S_IFREG | 0o7777, 0}, canCreate},
			{"whiteout char device", [6]uint64{10, 0x1000, unix.S_IFCHR, 0}, canCreate},
			{"whiteout char device with perms", [6]uint64{10, 0x1000, unix.S_IFCHR | 0o644, 0}, canCreate},
			{"non-whiteout char device", [6]uint64{10, 0x1000, unix.S_IFCHR | 0o666, 0x0103}, false},
			{"regular file nonzero dev", [6]uint64{10, 0x1000, unix.S_IFREG | 0o644, 1}, false},
			{"dev high bits set", [6]uint64{10, 0x1000, unix.S_IFCHR, 1 << 32}, false},
			{"zero file type", [6]uint64{10, 0x1000, 0o644, 0}, false},
			{"fifo", [6]uint64{10, 0x1000, unix.S_IFIFO | 0o644, 0}, false},
			{"socket", [6]uint64{10, 0x1000, unix.S_IFSOCK | 0o644, 0}, false},
			{"block device", [6]uint64{10, 0x1000, unix.S_IFBLK | 0o644, 0}, false},
			{"directory", [6]uint64{10, 0x1000, unix.S_IFDIR | 0o755, 0}, false},
			{"symlink", [6]uint64{10, 0x1000, unix.S_IFLNK | 0o777, 0}, false},
			{"AT_FDCWD 32-bit", [6]uint64{uint64(uint32(atFDCWD32)), 0x1000, unix.S_IFREG | 0o644, 0}, false},
			{"AT_FDCWD 64-bit", [6]uint64{uint64(atFDCWD64), 0x1000, unix.S_IFREG | 0o644, 0}, false},
			{"negative FD", [6]uint64{^uint64(0), 0x1000, unix.S_IFREG | 0o644, 0}, false},
		} {
			if allowed := filterAllows(t, compiled, unix.SYS_MKNODAT, tc.args); allowed != tc.allowed {
				t.Errorf("HostFS=%v %s: allowed=%t, want %t", hostFS, tc.name, allowed, tc.allowed)
			}
		}
	}
}

// TestHostFSAccess verifies which host filesystem syscalls each level of
// HostFSAccess allows.
func TestHostFSAccess(t *testing.T) {
	const (
		dirFD      = 10
		procSelfFD = 7
		ptr        = 0x1000
		// never is higher than every level.
		never = HostFSReadWrite + 1
		// openFlags are the flags that every open by directfs has.
		openFlags = unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NOCTTY
		// reopenFlags are the flags that every reopen by directfs has.
		reopenFlags = unix.O_CLOEXEC | unix.O_NOCTTY
	)
	atFDCWD := int64(linux.AT_FDCWD)
	compiled := make(map[HostFSAccess]bpf.Program)
	for hostFS := HostFSNone; hostFS < never; hostFS++ {
		compiled[hostFS] = compileFilter(t, Options{
			HostFS:     hostFS,
			ProcSelfFD: procSelfFD,
			Platform:   (&systrap.Systrap{}).SeccompInfo(),
		})
	}
	instrumentation := instrumentationFilters()
	for _, tc := range []struct {
		name  string
		sysno uintptr
		args  [6]uint64
		// from is the lowest level that allows the syscall.
		from HostFSAccess
	}{
		{"look up", unix.SYS_OPENAT, [6]uint64{dirFD, ptr, unix.O_RDONLY | unix.O_NONBLOCK | openFlags}, HostFSReadOnly},
		{"look up with O_PATH", unix.SYS_OPENAT, [6]uint64{dirFD, ptr, unix.O_PATH | openFlags}, HostFSReadOnly},
		{"look up directory", unix.SYS_OPENAT, [6]uint64{dirFD, ptr, unix.O_RDONLY | unix.O_NONBLOCK | unix.O_DIRECTORY | openFlags}, HostFSReadOnly},
		{"look up and follow symlink", unix.SYS_OPENAT, [6]uint64{dirFD, ptr, unix.O_RDONLY | unix.O_CLOEXEC}, never},
		{"look up from AT_FDCWD", unix.SYS_OPENAT, [6]uint64{uint64(atFDCWD), ptr, unix.O_RDONLY | openFlags}, never},
		{"open child write-only", unix.SYS_OPENAT, [6]uint64{dirFD, ptr, unix.O_WRONLY | openFlags}, HostFSReadWrite},
		{"open child read-write", unix.SYS_OPENAT, [6]uint64{dirFD, ptr, unix.O_RDWR | openFlags}, HostFSReadWrite},
		{"open child and truncate", unix.SYS_OPENAT, [6]uint64{dirFD, ptr, unix.O_RDONLY | unix.O_TRUNC | openFlags}, HostFSReadWrite},
		{"create child", unix.SYS_OPENAT, [6]uint64{dirFD, ptr, unix.O_CREAT | unix.O_EXCL | unix.O_RDWR | openFlags, 0o644}, HostFSReadWrite},
		{"create unnamed child", unix.SYS_OPENAT, [6]uint64{dirFD, ptr, unix.O_TMPFILE | unix.O_RDWR | openFlags, 0o644}, HostFSReadWrite},
		{"reopen read-only", unix.SYS_OPENAT, [6]uint64{procSelfFD, ptr, unix.O_RDONLY | reopenFlags}, HostFSReadOnly},
		{"reopen read-write", unix.SYS_OPENAT, [6]uint64{procSelfFD, ptr, unix.O_RDWR | reopenFlags}, HostFSReadOnly},
		{"reopen and truncate", unix.SYS_OPENAT, [6]uint64{procSelfFD, ptr, unix.O_WRONLY | unix.O_TRUNC | reopenFlags}, HostFSReadOnly},
		{"reopen and create", unix.SYS_OPENAT, [6]uint64{procSelfFD, ptr, unix.O_RDWR | unix.O_CREAT | reopenFlags, 0o644}, never},
		{"reopen as unnamed file", unix.SYS_OPENAT, [6]uint64{procSelfFD, ptr, unix.O_RDWR | unix.O_TMPFILE | reopenFlags, 0o644}, never},
		{"getdents64", unix.SYS_GETDENTS64, [6]uint64{dirFD, ptr, 4096}, HostFSReadOnly},
		{"readlinkat", unix.SYS_READLINKAT, [6]uint64{dirFD, ptr, ptr, 128}, HostFSReadOnly},
		{"statx by name", unix.SYS_STATX, [6]uint64{dirFD, ptr, unix.AT_SYMLINK_NOFOLLOW | unix.AT_NO_AUTOMOUNT, unix.STATX_BASIC_STATS, ptr}, HostFSReadOnly},
		{"fstatat", archFstatAtSysNo(), [6]uint64{dirFD, ptr, ptr, unix.AT_SYMLINK_NOFOLLOW}, HostFSReadOnly},
		{"fgetxattr", unix.SYS_FGETXATTR, [6]uint64{dirFD, ptr, ptr, 128}, HostFSReadOnly},
		{"flistxattr", unix.SYS_FLISTXATTR, [6]uint64{dirFD, ptr, 128}, HostFSReadOnly},
		{"fsetxattr", unix.SYS_FSETXATTR, [6]uint64{dirFD, ptr, ptr, 8, 0}, HostFSReadOnly},
		{"fremovexattr", unix.SYS_FREMOVEXATTR, [6]uint64{dirFD, ptr}, HostFSReadOnly},
		{"fchmod", unix.SYS_FCHMOD, [6]uint64{dirFD, 0o644}, HostFSReadWrite},
		{"fchmodat", unix.SYS_FCHMODAT, [6]uint64{procSelfFD, ptr, 0o644}, HostFSReadWrite},
		{"fchownat", unix.SYS_FCHOWNAT, [6]uint64{dirFD, ptr, 1, 1, unix.AT_EMPTY_PATH | unix.AT_SYMLINK_NOFOLLOW}, HostFSReadWrite},
		{"utimensat by name", unix.SYS_UTIMENSAT, [6]uint64{procSelfFD, ptr, ptr, 0}, HostFSReadWrite},
		{"mkdirat", unix.SYS_MKDIRAT, [6]uint64{dirFD, ptr, 0o755}, HostFSReadWrite},
		{"mknodat", unix.SYS_MKNODAT, [6]uint64{dirFD, ptr, unix.S_IFREG | 0o644, 0}, HostFSReadWrite},
		{"symlinkat", unix.SYS_SYMLINKAT, [6]uint64{ptr, dirFD, ptr}, HostFSReadWrite},
		{"linkat", unix.SYS_LINKAT, [6]uint64{procSelfFD, ptr, dirFD, ptr, unix.AT_SYMLINK_FOLLOW}, HostFSReadWrite},
		{"renameat2", unix.SYS_RENAMEAT2, [6]uint64{dirFD, ptr, dirFD, ptr, 0}, HostFSReadWrite},
		{"unlinkat", unix.SYS_UNLINKAT, [6]uint64{dirFD, ptr, 0}, HostFSReadWrite},
	} {
		// Instrumentation such as -race can allow a syscall for every
		// configuration.
		_, instrumented := instrumentation.Get(tc.sysno).(seccomp.MatchAll)
		for hostFS, program := range compiled {
			if allowed, want := filterAllows(t, program, tc.sysno, tc.args), instrumented || hostFS >= tc.from; allowed != want {
				t.Errorf("HostFS=%v %s: allowed=%t, want %t", hostFS, tc.name, allowed, want)
			}
		}
	}
}
