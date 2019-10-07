// Copyright 2019 The gVisor Authors.
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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/syscalls"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
)

// ARM64 is a table of Linux arm64 syscall API with the corresponding syscall
// numbers from Linux 4.4.
var ARM64 = &kernel.SyscallTable{
	OS:   abi.Linux,
	Arch: arch.ARM64,
	Version: kernel.Version{
		Sysname: _LINUX_SYSNAME,
		Release: _LINUX_RELEASE,
		Version: _LINUX_VERSION,
	},
	AuditNumber: linux.AUDIT_ARCH_AARCH64,
	Table: map[uintptr]kernel.Syscall{
		0:   syscalls.PartiallySupported("io_setup", IoSetup, "Generally supported with exceptions. User ring optimizations are not implemented.", []string{"gvisor.dev/issue/204"}),
		1:   syscalls.PartiallySupported("io_destroy", IoDestroy, "Generally supported with exceptions. User ring optimizations are not implemented.", []string{"gvisor.dev/issue/204"}),
		2:   syscalls.PartiallySupported("io_submit", IoSubmit, "Generally supported with exceptions. User ring optimizations are not implemented.", []string{"gvisor.dev/issue/204"}),
		3:   syscalls.PartiallySupported("io_cancel", IoCancel, "Generally supported with exceptions. User ring optimizations are not implemented.", []string{"gvisor.dev/issue/204"}),
		4:   syscalls.PartiallySupported("io_getevents", IoGetevents, "Generally supported with exceptions. User ring optimizations are not implemented.", []string{"gvisor.dev/issue/204"}),
		5:   syscalls.Error("setxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		6:   syscalls.Error("lsetxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		7:   syscalls.Error("fsetxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		8:   syscalls.ErrorWithEvent("getxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		9:   syscalls.ErrorWithEvent("lgetxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		10:  syscalls.ErrorWithEvent("fgetxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		11:  syscalls.ErrorWithEvent("listxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		12:  syscalls.ErrorWithEvent("llistxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		13:  syscalls.ErrorWithEvent("flistxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		14:  syscalls.ErrorWithEvent("removexattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		15:  syscalls.ErrorWithEvent("lremovexattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		16:  syscalls.ErrorWithEvent("fremovexattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		17:  syscalls.Supported("getcwd", Getcwd),
		18:  syscalls.CapError("lookup_dcookie", linux.CAP_SYS_ADMIN, "", nil),
		19:  syscalls.Supported("eventfd2", Eventfd2),
		20:  syscalls.Supported("epoll_create1", EpollCreate1),
		21:  syscalls.Supported("epoll_ctl", EpollCtl),
		22:  syscalls.Supported("epoll_pwait", EpollPwait),
		23:  syscalls.Supported("dup", Dup),
		24:  syscalls.Supported("dup3", Dup3),
		26:  syscalls.Supported("inotify_init1", InotifyInit1),
		27:  syscalls.PartiallySupported("inotify_add_watch", InotifyAddWatch, "inotify events are only available inside the sandbox.", nil),
		28:  syscalls.PartiallySupported("inotify_rm_watch", InotifyRmWatch, "inotify events are only available inside the sandbox.", nil),
		29:  syscalls.PartiallySupported("ioctl", Ioctl, "Only a few ioctls are implemented for backing devices and file systems.", nil),
		30:  syscalls.CapError("ioprio_set", linux.CAP_SYS_ADMIN, "", nil), // requires cap_sys_nice or cap_sys_admin (depending)
		31:  syscalls.CapError("ioprio_get", linux.CAP_SYS_ADMIN, "", nil), // requires cap_sys_nice or cap_sys_admin (depending)
		32:  syscalls.PartiallySupported("flock", Flock, "Locks are held within the sandbox only.", nil),
		33:  syscalls.Supported("mknodat", Mknodat),
		34:  syscalls.Supported("mkdirat", Mkdirat),
		35:  syscalls.Supported("unlinkat", Unlinkat),
		36:  syscalls.Supported("symlinkat", Symlinkat),
		37:  syscalls.Supported("linkat", Linkat),
		38:  syscalls.Supported("renameat", Renameat),
		39:  syscalls.PartiallySupported("umount2", Umount2, "Not all options or file systems are supported.", nil),
		40:  syscalls.PartiallySupported("mount", Mount, "Not all options or file systems are supported.", nil),
		41:  syscalls.Error("pivot_root", syserror.EPERM, "", nil),
		42:  syscalls.Error("nfsservctl", syserror.ENOSYS, "Removed after Linux 3.1.", nil),
		44:  syscalls.PartiallySupported("fstatfs", Fstatfs, "Depends on the backing file system implementation.", nil),
		46:  syscalls.Supported("ftruncate", Ftruncate),
		47:  syscalls.PartiallySupported("fallocate", Fallocate, "Not all options are supported.", nil),
		48:  syscalls.Supported("faccessat", Faccessat),
		49:  syscalls.Supported("chdir", Chdir),
		50:  syscalls.Supported("fchdir", Fchdir),
		51:  syscalls.Supported("chroot", Chroot),
		52:  syscalls.PartiallySupported("fchmod", Fchmod, "Options S_ISUID and S_ISGID not supported.", nil),
		53:  syscalls.Supported("fchmodat", Fchmodat),
		54:  syscalls.Supported("fchownat", Fchownat),
		55:  syscalls.Supported("fchown", Fchown),
		56:  syscalls.Supported("openat", Openat),
		57:  syscalls.Supported("close", Close),
		58:  syscalls.CapError("vhangup", linux.CAP_SYS_TTY_CONFIG, "", nil),
		59:  syscalls.Supported("pipe2", Pipe2),
		60:  syscalls.CapError("quotactl", linux.CAP_SYS_ADMIN, "", nil), // requires cap_sys_admin for most operations
		61:  syscalls.Supported("getdents64", Getdents64),
		62:  syscalls.Supported("lseek", Lseek),
		63:  syscalls.Supported("read", Read),
		64:  syscalls.Supported("write", Write),
		65:  syscalls.Supported("readv", Readv),
		66:  syscalls.Supported("writev", Writev),
		67:  syscalls.Supported("pread64", Pread64),
		68:  syscalls.Supported("pwrite64", Pwrite64),
		69:  syscalls.Supported("preadv", Preadv),
		70:  syscalls.Supported("pwritev", Pwritev),
		71:  syscalls.Supported("sendfile", Sendfile),
		72:  syscalls.Supported("pselect", Pselect),
		73:  syscalls.Supported("ppoll", Ppoll),
		74:  syscalls.ErrorWithEvent("signalfd4", syserror.ENOSYS, "", []string{"gvisor.dev/issue/139"}),             // TODO(b/19846426)
		75:  syscalls.ErrorWithEvent("vmsplice", syserror.ENOSYS, "", []string{"gvisor.dev/issue/138"}),              // TODO(b/29354098)
		76:  syscalls.PartiallySupported("splice", Splice, "Stub implementation.", []string{"gvisor.dev/issue/138"}), // TODO(b/29354098)
		77:  syscalls.ErrorWithEvent("tee", syserror.ENOSYS, "", []string{"gvisor.dev/issue/138"}),                   // TODO(b/29354098)
		78:  syscalls.Supported("readlinkat", Readlinkat),
		80:  syscalls.Supported("fstat", Fstat),
		81:  syscalls.PartiallySupported("sync", Sync, "Full data flush is not guaranteed at this time.", nil),
		82:  syscalls.PartiallySupported("fsync", Fsync, "Full data flush is not guaranteed at this time.", nil),
		83:  syscalls.PartiallySupported("fdatasync", Fdatasync, "Full data flush is not guaranteed at this time.", nil),
		84:  syscalls.PartiallySupported("sync_file_range", SyncFileRange, "Full data flush is not guaranteed at this time.", nil),
		85:  syscalls.Supported("timerfd_create", TimerfdCreate),
		86:  syscalls.Supported("timerfd_settime", TimerfdSettime),
		87:  syscalls.Supported("timerfd_gettime", TimerfdGettime),
		88:  syscalls.Supported("utimensat", Utimensat),
		89:  syscalls.CapError("acct", linux.CAP_SYS_PACCT, "", nil),
		90:  syscalls.Supported("capget", Capget),
		91:  syscalls.Supported("capset", Capset),
		92:  syscalls.ErrorWithEvent("personality", syserror.EINVAL, "Unable to change personality.", nil),
		93:  syscalls.Supported("exit", Exit),
		94:  syscalls.Supported("exit_group", ExitGroup),
		95:  syscalls.Supported("waitid", Waitid),
		96:  syscalls.Supported("set_tid_address", SetTidAddress),
		97:  syscalls.PartiallySupported("unshare", Unshare, "Mount, cgroup namespaces not supported. Network namespaces supported but must be empty.", nil),
		98:  syscalls.PartiallySupported("futex", Futex, "Robust futexes not supported.", nil),
		99:  syscalls.Error("set_robust_list", syserror.ENOSYS, "Obsolete.", nil),
		100: syscalls.Error("get_robust_list", syserror.ENOSYS, "Obsolete.", nil),
		101: syscalls.Supported("nanosleep", Nanosleep),
		102: syscalls.Supported("getitimer", Getitimer),
		103: syscalls.Supported("setitimer", Setitimer),
		104: syscalls.CapError("kexec_load", linux.CAP_SYS_BOOT, "", nil),
		105: syscalls.CapError("init_module", linux.CAP_SYS_MODULE, "", nil),
		106: syscalls.CapError("delete_module", linux.CAP_SYS_MODULE, "", nil),
		107: syscalls.Supported("timer_create", TimerCreate),
		108: syscalls.Supported("timer_gettime", TimerGettime),
		109: syscalls.Supported("timer_getoverrun", TimerGetoverrun),
		110: syscalls.Supported("timer_settime", TimerSettime),
		111: syscalls.Supported("timer_delete", TimerDelete),
		112: syscalls.Supported("clock_settime", ClockSettime),
		113: syscalls.Supported("clock_gettime", ClockGettime),
		114: syscalls.Supported("clock_getres", ClockGetres),
		115: syscalls.Supported("clock_nanosleep", ClockNanosleep),
		116: syscalls.PartiallySupported("syslog", Syslog, "Outputs a dummy message for security reasons.", nil),
		117: syscalls.PartiallySupported("ptrace", Ptrace, "Options PTRACE_PEEKSIGINFO, PTRACE_SECCOMP_GET_FILTER not supported.", nil),
		118: syscalls.CapError("sched_setparam", linux.CAP_SYS_NICE, "", nil),
		119: syscalls.PartiallySupported("sched_setscheduler", SchedSetscheduler, "Stub implementation.", nil),
		120: syscalls.PartiallySupported("sched_getscheduler", SchedGetscheduler, "Stub implementation.", nil),
		121: syscalls.PartiallySupported("sched_getparam", SchedGetparam, "Stub implementation.", nil),
		122: syscalls.PartiallySupported("sched_setaffinity", SchedSetaffinity, "Stub implementation.", nil),
		123: syscalls.PartiallySupported("sched_getaffinity", SchedGetaffinity, "Stub implementation.", nil),
		124: syscalls.Supported("sched_yield", SchedYield),
		125: syscalls.PartiallySupported("sched_get_priority_max", SchedGetPriorityMax, "Stub implementation.", nil),
		126: syscalls.PartiallySupported("sched_get_priority_min", SchedGetPriorityMin, "Stub implementation.", nil),
		127: syscalls.ErrorWithEvent("sched_rr_get_interval", syserror.EPERM, "", nil),
		128: syscalls.Supported("restart_syscall", RestartSyscall),
		129: syscalls.Supported("kill", Kill),
		130: syscalls.Supported("tkill", Tkill),
		131: syscalls.Supported("tgkill", Tgkill),
		132: syscalls.Supported("sigaltstack", Sigaltstack),
		133: syscalls.Supported("rt_sigsuspend", RtSigsuspend),
		134: syscalls.Supported("rt_sigaction", RtSigaction),
		135: syscalls.Supported("rt_sigprocmask", RtSigprocmask),
		136: syscalls.Supported("rt_sigpending", RtSigpending),
		137: syscalls.Supported("rt_sigtimedwait", RtSigtimedwait),
		138: syscalls.Supported("rt_sigqueueinfo", RtSigqueueinfo),
		139: syscalls.Supported("rt_sigreturn", RtSigreturn),
		140: syscalls.PartiallySupported("setpriority", Setpriority, "Stub implementation.", nil),
		141: syscalls.PartiallySupported("getpriority", Getpriority, "Stub implementation.", nil),
		142: syscalls.CapError("reboot", linux.CAP_SYS_BOOT, "", nil),
		143: syscalls.Supported("setregid", Setregid),
		144: syscalls.Supported("setgid", Setgid),
		145: syscalls.Supported("setreuid", Setreuid),
		146: syscalls.Supported("setuid", Setuid),
		147: syscalls.Supported("setresuid", Setresuid),
		148: syscalls.Supported("getresuid", Getresuid),
		149: syscalls.Supported("setresgid", Setresgid),
		150: syscalls.Supported("getresgid", Getresgid),
		151: syscalls.ErrorWithEvent("setfsuid", syserror.ENOSYS, "", []string{"gvisor.dev/issue/260"}), // TODO(b/112851702)
		152: syscalls.ErrorWithEvent("setfsgid", syserror.ENOSYS, "", []string{"gvisor.dev/issue/260"}), // TODO(b/112851702)
		153: syscalls.Supported("times", Times),
		154: syscalls.Supported("setpgid", Setpgid),
		155: syscalls.Supported("getpgid", Getpgid),
		156: syscalls.Supported("getsid", Getsid),
		157: syscalls.Supported("setsid", Setsid),
		158: syscalls.Supported("getgroups", Getgroups),
		159: syscalls.Supported("setgroups", Setgroups),
		160: syscalls.Supported("uname", Uname),
		161: syscalls.Supported("sethostname", Sethostname),
		162: syscalls.Supported("setdomainname", Setdomainname),
		163: syscalls.Supported("getrlimit", Getrlimit),
		164: syscalls.PartiallySupported("setrlimit", Setrlimit, "Not all rlimits are enforced.", nil),
		165: syscalls.PartiallySupported("getrusage", Getrusage, "Fields ru_maxrss, ru_minflt, ru_majflt, ru_inblock, ru_oublock are not supported. Fields ru_utime and ru_stime have low precision.", nil),
		166: syscalls.Supported("umask", Umask),
		167: syscalls.PartiallySupported("prctl", Prctl, "Not all options are supported.", nil),
		168: syscalls.Supported("getcpu", Getcpu),
		169: syscalls.Supported("gettimeofday", Gettimeofday),
		170: syscalls.CapError("settimeofday", linux.CAP_SYS_TIME, "", nil),
		171: syscalls.CapError("adjtimex", linux.CAP_SYS_TIME, "", nil),
		172: syscalls.Supported("getpid", Getpid),
		173: syscalls.Supported("getppid", Getppid),
		174: syscalls.Supported("getuid", Getuid),
		175: syscalls.Supported("geteuid", Geteuid),
		176: syscalls.Supported("getgid", Getgid),
		177: syscalls.Supported("getegid", Getegid),
		178: syscalls.Supported("gettid", Gettid),
		179: syscalls.PartiallySupported("sysinfo", Sysinfo, "Fields loads, sharedram, bufferram, totalswap, freeswap, totalhigh, freehigh not supported.", nil),
		180: syscalls.ErrorWithEvent("mq_open", syserror.ENOSYS, "", []string{"gvisor.dev/issue/136"}),         // TODO(b/29354921)
		181: syscalls.ErrorWithEvent("mq_unlink", syserror.ENOSYS, "", []string{"gvisor.dev/issue/136"}),       // TODO(b/29354921)
		182: syscalls.ErrorWithEvent("mq_timedsend", syserror.ENOSYS, "", []string{"gvisor.dev/issue/136"}),    // TODO(b/29354921)
		183: syscalls.ErrorWithEvent("mq_timedreceive", syserror.ENOSYS, "", []string{"gvisor.dev/issue/136"}), // TODO(b/29354921)
		184: syscalls.ErrorWithEvent("mq_notify", syserror.ENOSYS, "", []string{"gvisor.dev/issue/136"}),       // TODO(b/29354921)
		185: syscalls.ErrorWithEvent("mq_getsetattr", syserror.ENOSYS, "", []string{"gvisor.dev/issue/136"}),   // TODO(b/29354921)
		186: syscalls.ErrorWithEvent("msgget", syserror.ENOSYS, "", []string{"gvisor.dev/issue/135"}),          // TODO(b/29354921)
		187: syscalls.ErrorWithEvent("msgctl", syserror.ENOSYS, "", []string{"gvisor.dev/issue/135"}),          // TODO(b/29354921)
		188: syscalls.ErrorWithEvent("msgrcv", syserror.ENOSYS, "", []string{"gvisor.dev/issue/135"}),          // TODO(b/29354921)
		189: syscalls.ErrorWithEvent("msgsnd", syserror.ENOSYS, "", []string{"gvisor.dev/issue/135"}),          // TODO(b/29354921)
		190: syscalls.Supported("semget", Semget),
		191: syscalls.PartiallySupported("semctl", Semctl, "Options IPC_INFO, SEM_INFO, IPC_STAT, SEM_STAT, SEM_STAT_ANY, GETNCNT, GETZCNT not supported.", nil),
		192: syscalls.ErrorWithEvent("semtimedop", syserror.ENOSYS, "", []string{"gvisor.dev/issue/137"}), // TODO(b/29354920)
		193: syscalls.PartiallySupported("semop", Semop, "Option SEM_UNDO not supported.", nil),
		194: syscalls.PartiallySupported("shmget", Shmget, "Option SHM_HUGETLB is not supported.", nil),
		195: syscalls.PartiallySupported("shmctl", Shmctl, "Options SHM_LOCK, SHM_UNLOCK are not supported.", nil),
		196: syscalls.PartiallySupported("shmat", Shmat, "Option SHM_RND is not supported.", nil),
		197: syscalls.Supported("shmdt", Shmdt),
		198: syscalls.PartiallySupported("socket", Socket, "Limited support for AF_NETLINK, NETLINK_ROUTE sockets. Limited support for SOCK_RAW.", nil),
		199: syscalls.Supported("socketpair", SocketPair),
		200: syscalls.PartiallySupported("bind", Bind, "Autobind for abstract Unix sockets is not supported.", nil),
		201: syscalls.Supported("listen", Listen),
		202: syscalls.Supported("accept", Accept),
		203: syscalls.Supported("connect", Connect),
		204: syscalls.Supported("getsockname", GetSockName),
		205: syscalls.Supported("getpeername", GetPeerName),
		206: syscalls.Supported("sendto", SendTo),
		207: syscalls.Supported("recvfrom", RecvFrom),
		208: syscalls.PartiallySupported("setsockopt", SetSockOpt, "Not all socket options are supported.", nil),
		209: syscalls.PartiallySupported("getsockopt", GetSockOpt, "Not all socket options are supported.", nil),
		210: syscalls.PartiallySupported("shutdown", Shutdown, "Not all flags and control messages are supported.", nil),
		211: syscalls.Supported("sendmsg", SendMsg),
		212: syscalls.PartiallySupported("recvmsg", RecvMsg, "Not all flags and control messages are supported.", nil),
		213: syscalls.ErrorWithEvent("readahead", syserror.ENOSYS, "", []string{"gvisor.dev/issue/261"}), // TODO(b/29351341)
		214: syscalls.Supported("brk", Brk),
		215: syscalls.Supported("munmap", Munmap),
		216: syscalls.Supported("mremap", Mremap),
		217: syscalls.Error("add_key", syserror.EACCES, "Not available to user.", nil),
		218: syscalls.Error("request_key", syserror.EACCES, "Not available to user.", nil),
		219: syscalls.Error("keyctl", syserror.EACCES, "Not available to user.", nil),
		220: syscalls.PartiallySupported("clone", Clone, "Mount namespace (CLONE_NEWNS) not supported. Options CLONE_PARENT, CLONE_SYSVSEM not supported.", nil),
		221: syscalls.Supported("execve", Execve),
		224: syscalls.CapError("swapon", linux.CAP_SYS_ADMIN, "", nil),
		225: syscalls.CapError("swapoff", linux.CAP_SYS_ADMIN, "", nil),
		226: syscalls.Supported("mprotect", Mprotect),
		227: syscalls.PartiallySupported("msync", Msync, "Full data flush is not guaranteed at this time.", nil),
		228: syscalls.PartiallySupported("mlock", Mlock, "Stub implementation. The sandbox lacks appropriate permissions.", nil),
		229: syscalls.PartiallySupported("munlock", Munlock, "Stub implementation. The sandbox lacks appropriate permissions.", nil),
		230: syscalls.PartiallySupported("mlockall", Mlockall, "Stub implementation. The sandbox lacks appropriate permissions.", nil),
		231: syscalls.PartiallySupported("munlockall", Munlockall, "Stub implementation. The sandbox lacks appropriate permissions.", nil),
		232: syscalls.PartiallySupported("mincore", Mincore, "Stub implementation. The sandbox does not have access to this information. Reports all mapped pages are resident.", nil),
		233: syscalls.PartiallySupported("madvise", Madvise, "Options MADV_DONTNEED, MADV_DONTFORK are supported. Other advice is ignored.", nil),
		234: syscalls.ErrorWithEvent("remap_file_pages", syserror.ENOSYS, "Deprecated since Linux 3.16.", nil),
		235: syscalls.PartiallySupported("mbind", Mbind, "Stub implementation. Only a single NUMA node is advertised, and mempolicy is ignored accordingly, but mbind() will succeed and has effects reflected by get_mempolicy.", []string{"gvisor.dev/issue/262"}),
		236: syscalls.PartiallySupported("get_mempolicy", GetMempolicy, "Stub implementation.", nil),
		237: syscalls.PartiallySupported("set_mempolicy", SetMempolicy, "Stub implementation.", nil),
		238: syscalls.CapError("migrate_pages", linux.CAP_SYS_NICE, "", nil),
		239: syscalls.CapError("move_pages", linux.CAP_SYS_NICE, "", nil), // requires cap_sys_nice (mostly)
		240: syscalls.Supported("rt_tgsigqueueinfo", RtTgsigqueueinfo),
		241: syscalls.ErrorWithEvent("perf_event_open", syserror.ENODEV, "No support for perf counters", nil),
		242: syscalls.Supported("accept4", Accept4),
		243: syscalls.PartiallySupported("recvmmsg", RecvMMsg, "Not all flags and control messages are supported.", nil),
		260: syscalls.Supported("wait4", Wait4),
		261: syscalls.Supported("prlimit64", Prlimit64),
		262: syscalls.ErrorWithEvent("fanotify_init", syserror.ENOSYS, "Needs CONFIG_FANOTIFY", nil),
		263: syscalls.ErrorWithEvent("fanotify_mark", syserror.ENOSYS, "Needs CONFIG_FANOTIFY", nil),
		264: syscalls.Error("name_to_handle_at", syserror.EOPNOTSUPP, "Not supported by gVisor filesystems", nil),
		265: syscalls.Error("open_by_handle_at", syserror.EOPNOTSUPP, "Not supported by gVisor filesystems", nil),
		266: syscalls.CapError("clock_adjtime", linux.CAP_SYS_TIME, "", nil),
		267: syscalls.PartiallySupported("syncfs", Syncfs, "Depends on backing file system.", nil),
		268: syscalls.ErrorWithEvent("setns", syserror.EOPNOTSUPP, "Needs filesystem support", []string{"gvisor.dev/issue/140"}), // TODO(b/29354995)
		269: syscalls.PartiallySupported("sendmmsg", SendMMsg, "Not all flags and control messages are supported.", nil),
		270: syscalls.ErrorWithEvent("process_vm_readv", syserror.ENOSYS, "", []string{"gvisor.dev/issue/158"}),
		271: syscalls.ErrorWithEvent("process_vm_writev", syserror.ENOSYS, "", []string{"gvisor.dev/issue/158"}),
		272: syscalls.CapError("kcmp", linux.CAP_SYS_PTRACE, "", nil),
		273: syscalls.CapError("finit_module", linux.CAP_SYS_MODULE, "", nil),
		274: syscalls.ErrorWithEvent("sched_setattr", syserror.ENOSYS, "gVisor does not implement a scheduler.", []string{"gvisor.dev/issue/264"}), // TODO(b/118902272)
		275: syscalls.ErrorWithEvent("sched_getattr", syserror.ENOSYS, "gVisor does not implement a scheduler.", []string{"gvisor.dev/issue/264"}), // TODO(b/118902272)
		276: syscalls.ErrorWithEvent("renameat2", syserror.ENOSYS, "", []string{"gvisor.dev/issue/263"}),                                           // TODO(b/118902772)
		277: syscalls.Supported("seccomp", Seccomp),
		278: syscalls.Supported("getrandom", GetRandom),
		279: syscalls.Supported("memfd_create", MemfdCreate),
		280: syscalls.CapError("bpf", linux.CAP_SYS_ADMIN, "", nil),
		281: syscalls.ErrorWithEvent("execveat", syserror.ENOSYS, "", []string{"gvisor.dev/issue/265"}),    // TODO(b/118901836)
		282: syscalls.ErrorWithEvent("userfaultfd", syserror.ENOSYS, "", []string{"gvisor.dev/issue/266"}), // TODO(b/118906345)
		283: syscalls.ErrorWithEvent("membarrier", syserror.ENOSYS, "", []string{"gvisor.dev/issue/267"}),  // TODO(b/118904897)
		284: syscalls.PartiallySupported("mlock2", Mlock2, "Stub implementation. The sandbox lacks appropriate permissions.", nil),
		285: syscalls.ErrorWithEvent("copy_file_range", syserror.ENOSYS, "", nil),
		286: syscalls.Supported("preadv2", Preadv2),
		287: syscalls.PartiallySupported("pwritev2", Pwritev2, "Flag RWF_HIPRI is not supported.", nil),
		291: syscalls.Supported("statx", Statx),
	},
	Emulate: map[usermem.Addr]uintptr{},

	Missing: func(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
		t.Kernel().EmitUnimplementedEvent(t)
		return 0, syserror.ENOSYS
	},
}
