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
		//     68: Msgget, TODO
		//     69: Msgsnd, TODO
		//     70: Msgrcv, TODO
		//     71: Msgctl, TODO
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
		//     122: Setfsuid, TODO
		//     123: Setfsgid, TODO
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
		134: syscalls.Error(syscall.ENOSYS),          // Uselib, obsolete
		135: syscalls.ErrorWithEvent(syscall.EINVAL), // SetPersonality, unable to change personality
		136: syscalls.ErrorWithEvent(syscall.ENOSYS), // Ustat, needs filesystem support
		137: Statfs,
		138: Fstatfs,
		//     139: Sysfs, TODO
		140: Getpriority,
		141: Setpriority,
		142: syscalls.CapError(linux.CAP_SYS_NICE), // SchedSetparam, requires cap_sys_nice
		143: SchedGetparam,
		144: SchedSetscheduler,
		145: SchedGetscheduler,
		146: SchedGetPriorityMax,
		147: SchedGetPriorityMin,
		148: syscalls.ErrorWithEvent(syscall.EPERM),      // SchedRrGetInterval,
		149: syscalls.Error(nil),                         // Mlock, TODO
		150: syscalls.Error(nil),                         // Munlock, TODO
		151: syscalls.Error(nil),                         // Mlockall, TODO
		152: syscalls.Error(nil),                         // Munlockall, TODO
		153: syscalls.CapError(linux.CAP_SYS_TTY_CONFIG), // Vhangup,
		154: syscalls.Error(syscall.EPERM),               // ModifyLdt,
		155: syscalls.Error(syscall.EPERM),               // PivotRoot,
		156: syscalls.Error(syscall.EPERM),               // Sysctl, syscall is "worthless"
		157: Prctl,
		158: ArchPrctl,
		159: syscalls.CapError(linux.CAP_SYS_TIME), // Adjtimex, requires cap_sys_time
		160: Setrlimit,
		161: Chroot,
		162: Sync,
		163: syscalls.CapError(linux.CAP_SYS_PACCT), // Acct, requires cap_sys_pacct
		164: syscalls.CapError(linux.CAP_SYS_TIME),  // Settimeofday, requires cap_sys_time
		165: Mount,
		166: Umount2,
		167: syscalls.CapError(linux.CAP_SYS_ADMIN), // Swapon, requires cap_sys_admin
		168: syscalls.CapError(linux.CAP_SYS_ADMIN), // Swapoff, requires cap_sys_admin
		169: syscalls.CapError(linux.CAP_SYS_BOOT),  // Reboot, requires cap_sys_boot
		170: Sethostname,
		171: Setdomainname,
		172: syscalls.CapError(linux.CAP_SYS_RAWIO),  // Iopl, requires cap_sys_rawio
		173: syscalls.CapError(linux.CAP_SYS_RAWIO),  // Ioperm, requires cap_sys_rawio
		174: syscalls.CapError(linux.CAP_SYS_MODULE), // CreateModule, requires cap_sys_module
		175: syscalls.CapError(linux.CAP_SYS_MODULE), // InitModule, requires cap_sys_module
		176: syscalls.CapError(linux.CAP_SYS_MODULE), // DeleteModule, requires cap_sys_module
		177: syscalls.Error(syscall.ENOSYS),          // GetKernelSyms, not supported in > 2.6
		178: syscalls.Error(syscall.ENOSYS),          // QueryModule, not supported in > 2.6
		179: syscalls.CapError(linux.CAP_SYS_ADMIN),  // Quotactl, requires cap_sys_admin (most operations)
		180: syscalls.Error(syscall.ENOSYS),          // Nfsservctl, does not exist > 3.1
		181: syscalls.Error(syscall.ENOSYS),          // Getpmsg, not implemented in Linux
		182: syscalls.Error(syscall.ENOSYS),          // Putpmsg, not implemented in Linux
		183: syscalls.Error(syscall.ENOSYS),          // AfsSyscall, not implemented in Linux
		184: syscalls.Error(syscall.ENOSYS),          // Tuxcall, not implemented in Linux
		185: syscalls.Error(syscall.ENOSYS),          // Security, not implemented in Linux
		186: Gettid,
		187: nil,                                      // Readahead, TODO
		188: syscalls.ErrorWithEvent(syscall.ENOTSUP), // Setxattr, requires filesystem support
		189: syscalls.ErrorWithEvent(syscall.ENOTSUP), // Lsetxattr, requires filesystem support
		190: syscalls.ErrorWithEvent(syscall.ENOTSUP), // Fsetxattr, requires filesystem support
		191: syscalls.ErrorWithEvent(syscall.ENOTSUP), // Getxattr, requires filesystem support
		192: syscalls.ErrorWithEvent(syscall.ENOTSUP), // Lgetxattr, requires filesystem support
		193: syscalls.ErrorWithEvent(syscall.ENOTSUP), // Fgetxattr, requires filesystem support
		194: syscalls.ErrorWithEvent(syscall.ENOTSUP), // Listxattr, requires filesystem support
		195: syscalls.ErrorWithEvent(syscall.ENOTSUP), // Llistxattr, requires filesystem support
		196: syscalls.ErrorWithEvent(syscall.ENOTSUP), // Flistxattr, requires filesystem support
		197: syscalls.ErrorWithEvent(syscall.ENOTSUP), // Removexattr, requires filesystem support
		198: syscalls.ErrorWithEvent(syscall.ENOTSUP), // Lremovexattr, requires filesystem support
		199: syscalls.ErrorWithEvent(syscall.ENOTSUP), // Fremovexattr, requires filesystem support
		200: Tkill,
		201: Time,
		202: Futex,
		203: SchedSetaffinity,
		204: SchedGetaffinity,
		205: syscalls.Error(syscall.ENOSYS), // SetThreadArea, expected to return ENOSYS on 64-bit
		206: IoSetup,
		207: IoDestroy,
		208: IoGetevents,
		209: IoSubmit,
		210: IoCancel,
		211: syscalls.Error(syscall.ENOSYS),         // GetThreadArea, expected to return ENOSYS on 64-bit
		212: syscalls.CapError(linux.CAP_SYS_ADMIN), // LookupDcookie, requires cap_sys_admin
		213: EpollCreate,
		214: syscalls.ErrorWithEvent(syscall.ENOSYS), // EpollCtlOld, deprecated (afaik, unused)
		215: syscalls.ErrorWithEvent(syscall.ENOSYS), // EpollWaitOld, deprecated (afaik, unused)
		216: syscalls.ErrorWithEvent(syscall.ENOSYS), // RemapFilePages, deprecated since 3.16
		217: Getdents64,
		218: SetTidAddress,
		219: RestartSyscall,
		//     220: Semtimedop, TODO
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
		236: syscalls.Error(syscall.ENOSYS),        // Vserver, not implemented by Linux
		237: syscalls.CapError(linux.CAP_SYS_NICE), // Mbind, may require cap_sys_nice TODO
		238: SetMempolicy,
		239: GetMempolicy,
		//     240: MqOpen, TODO
		//     241: MqUnlink, TODO
		//     242: MqTimedsend, TODO
		//     243: MqTimedreceive, TODO
		//     244: MqNotify, TODO
		//     245: MqGetsetattr, TODO
		246: syscalls.CapError(linux.CAP_SYS_BOOT), // kexec_load, requires cap_sys_boot
		247: Waitid,
		248: syscalls.Error(syscall.EACCES),         // AddKey, not available to user
		249: syscalls.Error(syscall.EACCES),         // RequestKey, not available to user
		250: syscalls.Error(syscall.EACCES),         // Keyctl, not available to user
		251: syscalls.CapError(linux.CAP_SYS_ADMIN), // IoprioSet, requires cap_sys_nice or cap_sys_admin (depending)
		252: syscalls.CapError(linux.CAP_SYS_ADMIN), // IoprioGet, requires cap_sys_nice or cap_sys_admin (depending)
		253: InotifyInit,
		254: InotifyAddWatch,
		255: InotifyRmWatch,
		256: syscalls.CapError(linux.CAP_SYS_NICE), // MigratePages, requires cap_sys_nice
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
		273: syscalls.Error(syscall.ENOSYS), // SetRobustList, obsolete
		274: syscalls.Error(syscall.ENOSYS), // GetRobustList, obsolete
		275: Splice,
		276: Tee,
		277: SyncFileRange,
		278: Vmsplice,
		279: syscalls.CapError(linux.CAP_SYS_NICE), // MovePages, requires cap_sys_nice (mostly)
		280: Utimensat,
		281: EpollPwait,
		//     282: Signalfd, TODO
		283: TimerfdCreate,
		284: Eventfd,
		285: Fallocate,
		286: TimerfdSettime,
		287: TimerfdGettime,
		288: Accept4,
		//     289: Signalfd4, TODO
		290: Eventfd2,
		291: EpollCreate1,
		292: Dup3,
		293: Pipe2,
		294: InotifyInit1,
		295: Preadv,
		296: Pwritev,
		297: RtTgsigqueueinfo,
		298: syscalls.ErrorWithEvent(syscall.ENODEV), // PerfEventOpen, no support for perf counters
		299: RecvMMsg,
		300: syscalls.ErrorWithEvent(syscall.ENOSYS), // FanotifyInit, needs CONFIG_FANOTIFY
		301: syscalls.ErrorWithEvent(syscall.ENOSYS), // FanotifyMark, needs CONFIG_FANOTIFY
		302: Prlimit64,
		303: syscalls.ErrorWithEvent(syscall.EOPNOTSUPP), // NameToHandleAt, needs filesystem support
		304: syscalls.ErrorWithEvent(syscall.EOPNOTSUPP), // OpenByHandleAt, needs filesystem support
		305: syscalls.CapError(linux.CAP_SYS_TIME),       // ClockAdjtime, requires cap_sys_time
		306: Syncfs,
		307: SendMMsg,
		//     308: Setns, TODO
		309: Getcpu,
		//     310: ProcessVmReadv, TODO may require cap_sys_ptrace
		//     311: ProcessVmWritev, TODO may require cap_sys_ptrace
		312: syscalls.CapError(linux.CAP_SYS_PTRACE), // Kcmp, requires cap_sys_ptrace
		313: syscalls.CapError(linux.CAP_SYS_MODULE), // FinitModule, requires cap_sys_module
		//     314: SchedSetattr, TODO, we have no scheduler
		//     315: SchedGetattr, TODO, we have no scheduler
		//     316: Renameat2, TODO
		317: Seccomp,
		318: GetRandom,
		//     319: MemfdCreate, TODO
		320: syscalls.CapError(linux.CAP_SYS_BOOT),  // KexecFileLoad, infeasible to support
		321: syscalls.CapError(linux.CAP_SYS_ADMIN), // Bpf, requires cap_sys_admin for all commands
		//     322: Execveat, TODO
		//     323: Userfaultfd, TODO
		//     324: Membarrier, TODO
		// Syscalls after 325 are backports from 4.6.
		325: syscalls.Error(nil), // Mlock2, TODO
		327: Preadv2,
		//	328: Pwritev2,  // Pwritev2, TODO
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
