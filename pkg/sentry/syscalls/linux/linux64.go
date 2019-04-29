// Copyright 2018 Google LLC
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

// Package linux provides syscall tables for amd64 Linux.
package linux

import (
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/syscalls"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// AUDIT_ARCH_X86_64 identifies the Linux syscall API on AMD64, and is taken
// from <linux/audit.h>.
const _AUDIT_ARCH_X86_64 = 0xc000003e

// AMD64 is a table of Linux amd64 syscall API with the corresponding syscall
// numbers from Linux 4.4. The entries commented out are those syscalls we
// don't currently support.
//
// Syscall support is documented as annotations in Go comments of the form:
// @Syscall(<name>, <key:value>, ...)
//
// Supported args and values are:
//
// - arg: A syscall option. This entry only applies to the syscall when given
//        this option.
// - support: Indicates support level
//   - UNIMPLEMENTED: Unimplemented (default, implies returns:ENOSYS)
//   - PARTIAL: Partial support. Details should be provided in note.
//   - FULL: Full support
// - returns: Indicates a known return value. Values are syscall errors. This
//            is treated as a string so you can use something like
//            "returns:EPERM or ENOSYS".
// - issue: A Github issue number.
// - note: A note
//
// Example:
// // @Syscall(mmap, arg:MAP_PRIVATE, support:FULL, note:Private memory fully supported)
// // @Syscall(mmap, arg:MAP_SHARED, issue:123, note:Shared memory not supported)
// // @Syscall(setxattr, returns:ENOTSUP, note:Requires file system support)
//
// Annotations should be placed as close to their implementation as possible
// (preferrably as part of a supporting function's Godoc) and should be
// updated as syscall support changes. Unimplemented syscalls are documented
// here due to their lack of a supporting function or method.
var AMD64 = &kernel.SyscallTable{
	OS:   abi.Linux,
	Arch: arch.AMD64,
	Version: kernel.Version{
		// Version 4.4 is chosen as a stable, longterm version of Linux, which
		// guides the interface provided by this syscall table. The build
		// version is that for a clean build with default kernel config, at 5
		// minutes after v4.4 was tagged.
		Sysname: "Linux",
		Release: "4.4",
		Version: "#1 SMP Sun Jan 10 15:06:54 PST 2016",
	},
	AuditNumber: _AUDIT_ARCH_X86_64,
	Table: map[uintptr]kernel.SyscallFn{
		0:  Read,
		1:  Write,
		2:  Open,
		3:  Close,
		4:  Stat,
		5:  Fstat,
		6:  Lstat,
		7:  Poll,
		8:  Lseek,
		9:  Mmap,
		10: Mprotect,
		11: Munmap,
		12: Brk,
		13: RtSigaction,
		14: RtSigprocmask,
		15: RtSigreturn,
		16: Ioctl,
		17: Pread64,
		18: Pwrite64,
		19: Readv,
		20: Writev,
		21: Access,
		22: Pipe,
		23: Select,
		24: SchedYield,
		25: Mremap,
		26: Msync,
		27: Mincore,
		28: Madvise,
		29: Shmget,
		30: Shmat,
		31: Shmctl,
		32: Dup,
		33: Dup2,
		34: Pause,
		35: Nanosleep,
		36: Getitimer,
		37: Alarm,
		38: Setitimer,
		39: Getpid,
		40: Sendfile,
		41: Socket,
		42: Connect,
		43: Accept,
		44: SendTo,
		45: RecvFrom,
		46: SendMsg,
		47: RecvMsg,
		48: Shutdown,
		49: Bind,
		50: Listen,
		51: GetSockName,
		52: GetPeerName,
		53: SocketPair,
		54: SetSockOpt,
		55: GetSockOpt,
		56: Clone,
		57: Fork,
		58: Vfork,
		59: Execve,
		60: Exit,
		61: Wait4,
		62: Kill,
		63: Uname,
		64: Semget,
		65: Semop,
		66: Semctl,
		67: Shmdt,
		//     68: @Syscall(Msgget), TODO(b/29354921)
		//     69: @Syscall(Msgsnd), TODO(b/29354921)
		//     70: @Syscall(Msgrcv), TODO(b/29354921)
		//     71: @Syscall(Msgctl), TODO(b/29354921)
		72:  Fcntl,
		73:  Flock,
		74:  Fsync,
		75:  Fdatasync,
		76:  Truncate,
		77:  Ftruncate,
		78:  Getdents,
		79:  Getcwd,
		80:  Chdir,
		81:  Fchdir,
		82:  Rename,
		83:  Mkdir,
		84:  Rmdir,
		85:  Creat,
		86:  Link,
		87:  Unlink,
		88:  Symlink,
		89:  Readlink,
		90:  Chmod,
		91:  Fchmod,
		92:  Chown,
		93:  Fchown,
		94:  Lchown,
		95:  Umask,
		96:  Gettimeofday,
		97:  Getrlimit,
		98:  Getrusage,
		99:  Sysinfo,
		100: Times,
		101: Ptrace,
		102: Getuid,
		103: Syslog,
		104: Getgid,
		105: Setuid,
		106: Setgid,
		107: Geteuid,
		108: Getegid,
		109: Setpgid,
		110: Getppid,
		111: Getpgrp,
		112: Setsid,
		113: Setreuid,
		114: Setregid,
		115: Getgroups,
		116: Setgroups,
		117: Setresuid,
		118: Getresuid,
		119: Setresgid,
		120: Getresgid,
		121: Getpgid,
		//     122: @Syscall(Setfsuid), TODO(b/112851702)
		//     123: @Syscall(Setfsgid), TODO(b/112851702)
		124: Getsid,
		125: Capget,
		126: Capset,
		127: RtSigpending,
		128: RtSigtimedwait,
		129: RtSigqueueinfo,
		130: RtSigsuspend,
		131: Sigaltstack,
		132: Utime,
		133: Mknod,
		// @Syscall(Uselib, note:Obsolete)
		134: syscalls.Error(syscall.ENOSYS),
		// @Syscall(SetPersonality, returns:EINVAL, note:Unable to change personality)
		135: syscalls.ErrorWithEvent(syscall.EINVAL),
		// @Syscall(Ustat, note:Needs filesystem support)
		136: syscalls.ErrorWithEvent(syscall.ENOSYS),
		137: Statfs,
		138: Fstatfs,
		//     139: @Syscall(Sysfs), TODO(gvisor.dev/issue/165)
		140: Getpriority,
		141: Setpriority,
		// @Syscall(SchedSetparam, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_nice; ENOSYS otherwise)
		142: syscalls.CapError(linux.CAP_SYS_NICE), // requires cap_sys_nice
		143: SchedGetparam,
		144: SchedSetscheduler,
		145: SchedGetscheduler,
		146: SchedGetPriorityMax,
		147: SchedGetPriorityMin,
		// @Syscall(SchedRrGetInterval, returns:EPERM)
		148: syscalls.ErrorWithEvent(syscall.EPERM),
		149: Mlock,
		150: Munlock,
		151: Mlockall,
		152: Munlockall,
		// @Syscall(Vhangup, returns:EPERM)
		153: syscalls.CapError(linux.CAP_SYS_TTY_CONFIG),
		// @Syscall(ModifyLdt, returns:EPERM)
		154: syscalls.Error(syscall.EPERM),
		// @Syscall(PivotRoot, returns:EPERM)
		155: syscalls.Error(syscall.EPERM),
		// @Syscall(Sysctl, returns:EPERM)
		156: syscalls.Error(syscall.EPERM), // syscall is "worthless"
		157: Prctl,
		158: ArchPrctl,
		// @Syscall(Adjtimex, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_time; ENOSYS otherwise)
		159: syscalls.CapError(linux.CAP_SYS_TIME), // requires cap_sys_time
		160: Setrlimit,
		161: Chroot,
		162: Sync,
		// @Syscall(Acct, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_pacct; ENOSYS otherwise)
		163: syscalls.CapError(linux.CAP_SYS_PACCT), // requires cap_sys_pacct
		// @Syscall(Settimeofday, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_time; ENOSYS otherwise)
		164: syscalls.CapError(linux.CAP_SYS_TIME), // requires cap_sys_time
		165: Mount,
		166: Umount2,
		// @Syscall(Swapon, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise)
		167: syscalls.CapError(linux.CAP_SYS_ADMIN), // requires cap_sys_admin
		// @Syscall(Swapoff, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise)
		168: syscalls.CapError(linux.CAP_SYS_ADMIN), // requires cap_sys_admin
		// @Syscall(Reboot, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_boot; ENOSYS otherwise)
		169: syscalls.CapError(linux.CAP_SYS_BOOT), // requires cap_sys_boot
		170: Sethostname,
		171: Setdomainname,
		// @Syscall(Iopl, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_rawio; ENOSYS otherwise)
		172: syscalls.CapError(linux.CAP_SYS_RAWIO), // requires cap_sys_rawio
		// @Syscall(Ioperm, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_rawio; ENOSYS otherwise)
		173: syscalls.CapError(linux.CAP_SYS_RAWIO), // requires cap_sys_rawio
		// @Syscall(CreateModule, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise)
		174: syscalls.CapError(linux.CAP_SYS_MODULE), // CreateModule, requires cap_sys_module
		// @Syscall(InitModule, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise)
		175: syscalls.CapError(linux.CAP_SYS_MODULE), // requires cap_sys_module
		// @Syscall(DeleteModule, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise)
		176: syscalls.CapError(linux.CAP_SYS_MODULE), // requires cap_sys_module
		// @Syscall(GetKernelSyms, note:Not supported in > 2.6)
		177: syscalls.Error(syscall.ENOSYS),
		// @Syscall(QueryModule, note:Not supported in > 2.6)
		178: syscalls.Error(syscall.ENOSYS),
		// @Syscall(Quotactl, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise)
		179: syscalls.CapError(linux.CAP_SYS_ADMIN), // requires cap_sys_admin (most operations)
		// @Syscall(Nfsservctl, note:Does not exist > 3.1)
		180: syscalls.Error(syscall.ENOSYS),
		// @Syscall(Getpmsg, note:Not implemented in Linux)
		181: syscalls.Error(syscall.ENOSYS),
		// @Syscall(Putpmsg, note:Not implemented in Linux)
		182: syscalls.Error(syscall.ENOSYS),
		// @Syscall(AfsSyscall, note:Not implemented in Linux)
		183: syscalls.Error(syscall.ENOSYS),
		// @Syscall(Tuxcall, note:Not implemented in Linux)
		184: syscalls.Error(syscall.ENOSYS),
		// @Syscall(Security, note:Not implemented in Linux)
		185: syscalls.Error(syscall.ENOSYS),
		186: Gettid,
		187: nil, // @Syscall(Readahead), TODO(b/29351341)
		// @Syscall(Setxattr, returns:ENOTSUP, note:Requires filesystem support)
		188: syscalls.ErrorWithEvent(syscall.ENOTSUP),
		// @Syscall(Lsetxattr, returns:ENOTSUP, note:Requires filesystem support)
		189: syscalls.ErrorWithEvent(syscall.ENOTSUP),
		// @Syscall(Fsetxattr, returns:ENOTSUP, note:Requires filesystem support)
		190: syscalls.ErrorWithEvent(syscall.ENOTSUP),
		// @Syscall(Getxattr, returns:ENOTSUP, note:Requires filesystem support)
		191: syscalls.ErrorWithEvent(syscall.ENOTSUP),
		// @Syscall(Lgetxattr, returns:ENOTSUP, note:Requires filesystem support)
		192: syscalls.ErrorWithEvent(syscall.ENOTSUP),
		// @Syscall(Fgetxattr, returns:ENOTSUP, note:Requires filesystem support)
		193: syscalls.ErrorWithEvent(syscall.ENOTSUP),
		// @Syscall(Listxattr, returns:ENOTSUP, note:Requires filesystem support)
		194: syscalls.ErrorWithEvent(syscall.ENOTSUP),
		// @Syscall(Llistxattr, returns:ENOTSUP, note:Requires filesystem support)
		195: syscalls.ErrorWithEvent(syscall.ENOTSUP),
		// @Syscall(Flistxattr, returns:ENOTSUP, note:Requires filesystem support)
		196: syscalls.ErrorWithEvent(syscall.ENOTSUP),
		// @Syscall(Removexattr, returns:ENOTSUP, note:Requires filesystem support)
		197: syscalls.ErrorWithEvent(syscall.ENOTSUP),
		// @Syscall(Lremovexattr, returns:ENOTSUP, note:Requires filesystem support)
		198: syscalls.ErrorWithEvent(syscall.ENOTSUP),
		// @Syscall(Fremovexattr, returns:ENOTSUP, note:Requires filesystem support)
		199: syscalls.ErrorWithEvent(syscall.ENOTSUP),
		200: Tkill,
		201: Time,
		202: Futex,
		203: SchedSetaffinity,
		204: SchedGetaffinity,
		// @Syscall(SetThreadArea, note:Expected to return ENOSYS on 64-bit)
		205: syscalls.Error(syscall.ENOSYS),
		206: IoSetup,
		207: IoDestroy,
		208: IoGetevents,
		209: IoSubmit,
		210: IoCancel,
		// @Syscall(GetThreadArea, note:Expected to return ENOSYS on 64-bit)
		211: syscalls.Error(syscall.ENOSYS),
		// @Syscall(LookupDcookie, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise)
		212: syscalls.CapError(linux.CAP_SYS_ADMIN), // requires cap_sys_admin
		213: EpollCreate,
		// @Syscall(EpollCtlOld, note:Deprecated)
		214: syscalls.ErrorWithEvent(syscall.ENOSYS), // deprecated (afaik, unused)
		// @Syscall(EpollWaitOld, note:Deprecated)
		215: syscalls.ErrorWithEvent(syscall.ENOSYS), // deprecated (afaik, unused)
		// @Syscall(RemapFilePages, note:Deprecated)
		216: syscalls.ErrorWithEvent(syscall.ENOSYS), // deprecated since 3.16
		217: Getdents64,
		218: SetTidAddress,
		219: RestartSyscall,
		//     220: @Syscall(Semtimedop), TODO(b/29354920)
		221: Fadvise64,
		222: TimerCreate,
		223: TimerSettime,
		224: TimerGettime,
		225: TimerGetoverrun,
		226: TimerDelete,
		227: ClockSettime,
		228: ClockGettime,
		229: ClockGetres,
		230: ClockNanosleep,
		231: ExitGroup,
		232: EpollWait,
		233: EpollCtl,
		234: Tgkill,
		235: Utimes,
		// @Syscall(Vserver, note:Not implemented by Linux)
		236: syscalls.Error(syscall.ENOSYS), // Vserver, not implemented by Linux
		// @Syscall(Mbind, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_nice; ENOSYS otherwise), TODO(b/117792295)
		237: syscalls.CapError(linux.CAP_SYS_NICE), // may require cap_sys_nice
		238: SetMempolicy,
		239: GetMempolicy,
		//     240: @Syscall(MqOpen), TODO(b/29354921)
		//     241: @Syscall(MqUnlink), TODO(b/29354921)
		//     242: @Syscall(MqTimedsend), TODO(b/29354921)
		//     243: @Syscall(MqTimedreceive), TODO(b/29354921)
		//     244: @Syscall(MqNotify), TODO(b/29354921)
		//     245: @Syscall(MqGetsetattr), TODO(b/29354921)
		246: syscalls.CapError(linux.CAP_SYS_BOOT), // kexec_load, requires cap_sys_boot
		247: Waitid,
		// @Syscall(AddKey, returns:EACCES, note:Not available to user)
		248: syscalls.Error(syscall.EACCES),
		// @Syscall(RequestKey, returns:EACCES, note:Not available to user)
		249: syscalls.Error(syscall.EACCES),
		// @Syscall(Keyctl, returns:EACCES, note:Not available to user)
		250: syscalls.Error(syscall.EACCES),
		// @Syscall(IoprioSet, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise)
		251: syscalls.CapError(linux.CAP_SYS_ADMIN), // requires cap_sys_nice or cap_sys_admin (depending)
		// @Syscall(IoprioGet, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise)
		252: syscalls.CapError(linux.CAP_SYS_ADMIN), // requires cap_sys_nice or cap_sys_admin (depending)
		253: InotifyInit,
		254: InotifyAddWatch,
		255: InotifyRmWatch,
		// @Syscall(MigratePages, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_nice; ENOSYS otherwise)
		256: syscalls.CapError(linux.CAP_SYS_NICE),
		257: Openat,
		258: Mkdirat,
		259: Mknodat,
		260: Fchownat,
		261: Futimesat,
		262: Fstatat,
		263: Unlinkat,
		264: Renameat,
		265: Linkat,
		266: Symlinkat,
		267: Readlinkat,
		268: Fchmodat,
		269: Faccessat,
		270: Pselect,
		271: Ppoll,
		272: Unshare,
		// @Syscall(SetRobustList, note:Obsolete)
		273: syscalls.Error(syscall.ENOSYS),
		// @Syscall(GetRobustList, note:Obsolete)
		274: syscalls.Error(syscall.ENOSYS),
		//     275: @Syscall(Splice), TODO(b/29354098)
		//     276: @Syscall(Tee), TODO(b/29354098)
		277: SyncFileRange,
		//     278: @Syscall(Vmsplice), TODO(b/29354098)
		// @Syscall(MovePages, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_nice; ENOSYS otherwise)
		279: syscalls.CapError(linux.CAP_SYS_NICE), // requires cap_sys_nice (mostly)
		280: Utimensat,
		281: EpollPwait,
		//     282: @Syscall(Signalfd), TODO(b/19846426)
		283: TimerfdCreate,
		284: Eventfd,
		285: Fallocate,
		286: TimerfdSettime,
		287: TimerfdGettime,
		288: Accept4,
		//     289: @Syscall(Signalfd4), TODO(b/19846426)
		290: Eventfd2,
		291: EpollCreate1,
		292: Dup3,
		293: Pipe2,
		294: InotifyInit1,
		295: Preadv,
		296: Pwritev,
		297: RtTgsigqueueinfo,
		// @Syscall(PerfEventOpen, returns:ENODEV, note:No support for perf counters)
		298: syscalls.ErrorWithEvent(syscall.ENODEV),
		299: RecvMMsg,
		// @Syscall(FanotifyInit, note:Needs CONFIG_FANOTIFY)
		300: syscalls.ErrorWithEvent(syscall.ENOSYS),
		// @Syscall(FanotifyMark, note:Needs CONFIG_FANOTIFY)
		301: syscalls.ErrorWithEvent(syscall.ENOSYS),
		302: Prlimit64,
		// @Syscall(NameToHandleAt, returns:EOPNOTSUPP, note:Needs filesystem support)
		303: syscalls.ErrorWithEvent(syscall.EOPNOTSUPP),
		// @Syscall(OpenByHandleAt, returns:EOPNOTSUPP, note:Needs filesystem support)
		304: syscalls.ErrorWithEvent(syscall.EOPNOTSUPP),
		// @Syscall(ClockAdjtime, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise)
		305: syscalls.CapError(linux.CAP_SYS_TIME), // requires cap_sys_time
		306: Syncfs,
		307: SendMMsg,
		//     308: @Syscall(Setns), TODO(b/29354995)
		309: Getcpu,
		//     310: @Syscall(ProcessVmReadv), TODO(gvisor.dev/issue/158) may require cap_sys_ptrace
		//     311: @Syscall(ProcessVmWritev), TODO(gvisor.dev/issue/158) may require cap_sys_ptrace
		// @Syscall(Kcmp, returns:EPERM or ENOSYS, note:Requires cap_sys_ptrace)
		312: syscalls.CapError(linux.CAP_SYS_PTRACE),
		// @Syscall(FinitModule, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise)
		313: syscalls.CapError(linux.CAP_SYS_MODULE),
		//     314: @Syscall(SchedSetattr), TODO(b/118902272), we have no scheduler
		//     315: @Syscall(SchedGetattr), TODO(b/118902272), we have no scheduler
		//     316: @Syscall(Renameat2), TODO(b/118902772)
		317: Seccomp,
		318: GetRandom,
		319: MemfdCreate,
		// @Syscall(KexecFileLoad, EPERM or ENOSYS, note:Infeasible to support. Returns EPERM if the process does not have cap_sys_boot; ENOSYS otherwise)
		320: syscalls.CapError(linux.CAP_SYS_BOOT),
		// @Syscall(Bpf, returns:EPERM or ENOSYS, note:Returns EPERM if the process does not have cap_sys_boot; ENOSYS otherwise)
		321: syscalls.CapError(linux.CAP_SYS_ADMIN), // requires cap_sys_admin for all commands
		//     322: @Syscall(Execveat), TODO(b/118901836)
		//     323: @Syscall(Userfaultfd), TODO(b/118906345)
		//     324: @Syscall(Membarrier), TODO(b/118904897)
		325: Mlock2,
		// Syscalls after 325 are "backports" from versions of Linux after 4.4.
		//	326: @Syscall(CopyFileRange),
		327: Preadv2,
		328: Pwritev2,
	},

	Emulate: map[usermem.Addr]uintptr{
		0xffffffffff600000: 96,  // vsyscall gettimeofday(2)
		0xffffffffff600400: 201, // vsyscall time(2)
		0xffffffffff600800: 309, // vsyscall getcpu(2)
	},
	Missing: func(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
		t.Kernel().EmitUnimplementedEvent(t)
		return 0, syserror.ENOSYS
	},
}
