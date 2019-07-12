// Copyright 2018 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/syscalls"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
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
	Table: map[uintptr]kernel.Syscall{
		0:   syscalls.Supported("read", Read),
		1:   syscalls.Supported("write", Write),
		2:   syscalls.PartiallySupported("open", Open, "Options O_DIRECT, O_NOATIME, O_PATH, O_TMPFILE, O_SYNC are not supported.", nil),
		3:   syscalls.Supported("close", Close),
		4:   syscalls.Supported("stat", Stat),
		5:   syscalls.Supported("fstat", Fstat),
		6:   syscalls.Supported("lstat", Lstat),
		7:   syscalls.Supported("poll", Poll),
		8:   syscalls.Supported("lseek", Lseek),
		9:   syscalls.PartiallySupported("mmap", Mmap, "Generally supported with exceptions. Options MAP_FIXED_NOREPLACE, MAP_SHARED_VALIDATE, MAP_SYNC MAP_GROWSDOWN, MAP_HUGETLB are not supported.", nil),
		10:  syscalls.Supported("mprotect", Mprotect),
		11:  syscalls.Supported("munmap", Munmap),
		12:  syscalls.Supported("brk", Brk),
		13:  syscalls.Supported("rt_sigaction", RtSigaction),
		14:  syscalls.Supported("rt_sigprocmask", RtSigprocmask),
		15:  syscalls.Supported("rt_sigreturn", RtSigreturn),
		16:  syscalls.PartiallySupported("ioctl", Ioctl, "Only a few ioctls are implemented for backing devices and file systems.", nil),
		17:  syscalls.Supported("pread64", Pread64),
		18:  syscalls.Supported("pwrite64", Pwrite64),
		19:  syscalls.Supported("readv", Readv),
		20:  syscalls.Supported("writev", Writev),
		21:  syscalls.Supported("access", Access),
		22:  syscalls.Supported("pipe", Pipe),
		23:  syscalls.Supported("select", Select),
		24:  syscalls.Supported("sched_yield", SchedYield),
		25:  syscalls.Supported("mremap", Mremap),
		26:  syscalls.PartiallySupported("msync", Msync, "Full data flush is not guaranteed at this time.", nil),
		27:  syscalls.PartiallySupported("mincore", Mincore, "Stub implementation. The sandbox does not have access to this information. Reports all mapped pages are resident.", nil),
		28:  syscalls.PartiallySupported("madvise", Madvise, "Options MADV_DONTNEED, MADV_DONTFORK are supported. Other advice is ignored.", nil),
		29:  syscalls.PartiallySupported("shmget", Shmget, "Option SHM_HUGETLB is not supported.", nil),
		30:  syscalls.PartiallySupported("shmat", Shmat, "Option SHM_RND is not supported.", nil),
		31:  syscalls.PartiallySupported("shmctl", Shmctl, "Options SHM_LOCK, SHM_UNLOCK are not supported.", nil),
		32:  syscalls.Supported("dup", Dup),
		33:  syscalls.Supported("dup2", Dup2),
		34:  syscalls.Supported("pause", Pause),
		35:  syscalls.Supported("nanosleep", Nanosleep),
		36:  syscalls.Supported("getitimer", Getitimer),
		37:  syscalls.Supported("alarm", Alarm),
		38:  syscalls.Supported("setitimer", Setitimer),
		39:  syscalls.Supported("getpid", Getpid),
		40:  syscalls.Supported("sendfile", Sendfile),
		41:  syscalls.PartiallySupported("socket", Socket, "Limited support for AF_NETLINK, NETLINK_ROUTE sockets. Limited support for SOCK_RAW.", nil),
		42:  syscalls.Supported("connect", Connect),
		43:  syscalls.Supported("accept", Accept),
		44:  syscalls.Supported("sendto", SendTo),
		45:  syscalls.Supported("recvfrom", RecvFrom),
		46:  syscalls.Supported("sendmsg", SendMsg),
		47:  syscalls.PartiallySupported("recvmsg", RecvMsg, "Not all flags and control messages are supported.", nil),
		48:  syscalls.PartiallySupported("shutdown", Shutdown, "Not all flags and control messages are supported.", nil),
		49:  syscalls.PartiallySupported("bind", Bind, "Autobind for abstract Unix sockets is not supported.", nil),
		50:  syscalls.Supported("listen", Listen),
		51:  syscalls.Supported("getsockname", GetSockName),
		52:  syscalls.Supported("getpeername", GetPeerName),
		53:  syscalls.Supported("socketpair", SocketPair),
		54:  syscalls.PartiallySupported("setsockopt", SetSockOpt, "Not all socket options are supported.", nil),
		55:  syscalls.PartiallySupported("getsockopt", GetSockOpt, "Not all socket options are supported.", nil),
		56:  syscalls.PartiallySupported("clone", Clone, "Mount namespace (CLONE_NEWNS) not supported. Options CLONE_PARENT, CLONE_SYSVSEM not supported.", nil),
		57:  syscalls.Supported("fork", Fork),
		58:  syscalls.Supported("vfork", Vfork),
		59:  syscalls.Supported("execve", Execve),
		60:  syscalls.Supported("exit", Exit),
		61:  syscalls.Supported("wait4", Wait4),
		62:  syscalls.Supported("kill", Kill),
		63:  syscalls.Supported("uname", Uname),
		64:  syscalls.Supported("semget", Semget),
		65:  syscalls.PartiallySupported("semop", Semop, "Option SEM_UNDO not supported.", nil),
		66:  syscalls.PartiallySupported("semctl", Semctl, "Options IPC_INFO, SEM_INFO, IPC_STAT, SEM_STAT, SEM_STAT_ANY, GETNCNT, GETZCNT not supported.", nil),
		67:  syscalls.Supported("shmdt", Shmdt),
		68:  syscalls.ErrorWithEvent("msgget", syserror.ENOSYS, "", []string{"gvisor.dev/issue/135"}), // TODO(b/29354921)
		69:  syscalls.ErrorWithEvent("msgsnd", syserror.ENOSYS, "", []string{"gvisor.dev/issue/135"}), // TODO(b/29354921)
		70:  syscalls.ErrorWithEvent("msgrcv", syserror.ENOSYS, "", []string{"gvisor.dev/issue/135"}), // TODO(b/29354921)
		71:  syscalls.ErrorWithEvent("msgctl", syserror.ENOSYS, "", []string{"gvisor.dev/issue/135"}), // TODO(b/29354921)
		72:  syscalls.PartiallySupported("fcntl", Fcntl, "Not all options are supported.", nil),
		73:  syscalls.PartiallySupported("flock", Flock, "Locks are held within the sandbox only.", nil),
		74:  syscalls.PartiallySupported("fsync", Fsync, "Full data flush is not guaranteed at this time.", nil),
		75:  syscalls.PartiallySupported("fdatasync", Fdatasync, "Full data flush is not guaranteed at this time.", nil),
		76:  syscalls.Supported("truncate", Truncate),
		77:  syscalls.Supported("ftruncate", Ftruncate),
		78:  syscalls.Supported("getdents", Getdents),
		79:  syscalls.Supported("getcwd", Getcwd),
		80:  syscalls.Supported("chdir", Chdir),
		81:  syscalls.Supported("fchdir", Fchdir),
		82:  syscalls.Supported("rename", Rename),
		83:  syscalls.Supported("mkdir", Mkdir),
		84:  syscalls.Supported("rmdir", Rmdir),
		85:  syscalls.Supported("creat", Creat),
		86:  syscalls.Supported("link", Link),
		87:  syscalls.Supported("unlink", Unlink),
		88:  syscalls.Supported("symlink", Symlink),
		89:  syscalls.Supported("readlink", Readlink),
		90:  syscalls.Supported("chmod", Chmod),
		91:  syscalls.PartiallySupported("fchmod", Fchmod, "Options S_ISUID and S_ISGID not supported.", nil),
		92:  syscalls.Supported("chown", Chown),
		93:  syscalls.Supported("fchown", Fchown),
		94:  syscalls.Supported("lchown", Lchown),
		95:  syscalls.Supported("umask", Umask),
		96:  syscalls.Supported("gettimeofday", Gettimeofday),
		97:  syscalls.Supported("getrlimit", Getrlimit),
		98:  syscalls.PartiallySupported("getrusage", Getrusage, "Fields ru_maxrss, ru_minflt, ru_majflt, ru_inblock, ru_oublock are not supported. Fields ru_utime and ru_stime have low precision.", nil),
		99:  syscalls.PartiallySupported("sysinfo", Sysinfo, "Fields loads, sharedram, bufferram, totalswap, freeswap, totalhigh, freehigh not supported.", nil),
		100: syscalls.Supported("times", Times),
		101: syscalls.PartiallySupported("ptrace", Ptrace, "Options PTRACE_PEEKSIGINFO, PTRACE_SECCOMP_GET_FILTER not supported.", nil),
		102: syscalls.Supported("getuid", Getuid),
		103: syscalls.PartiallySupported("syslog", Syslog, "Outputs a dummy message for security reasons.", nil),
		104: syscalls.Supported("getgid", Getgid),
		105: syscalls.Supported("setuid", Setuid),
		106: syscalls.Supported("setgid", Setgid),
		107: syscalls.Supported("geteuid", Geteuid),
		108: syscalls.Supported("getegid", Getegid),
		109: syscalls.Supported("setpgid", Setpgid),
		110: syscalls.Supported("getppid", Getppid),
		111: syscalls.Supported("getpgrp", Getpgrp),
		112: syscalls.Supported("setsid", Setsid),
		113: syscalls.Supported("setreuid", Setreuid),
		114: syscalls.Supported("setregid", Setregid),
		115: syscalls.Supported("getgroups", Getgroups),
		116: syscalls.Supported("setgroups", Setgroups),
		117: syscalls.Supported("setresuid", Setresuid),
		118: syscalls.Supported("getresuid", Getresuid),
		119: syscalls.Supported("setresgid", Setresgid),
		120: syscalls.Supported("getresgid", Getresgid),
		121: syscalls.Supported("getpgid", Getpgid),
		122: syscalls.ErrorWithEvent("setfsuid", syserror.ENOSYS, "", []string{"gvisor.dev/issue/260"}), // TODO(b/112851702)
		123: syscalls.ErrorWithEvent("setfsgid", syserror.ENOSYS, "", []string{"gvisor.dev/issue/260"}), // TODO(b/112851702)
		124: syscalls.Supported("getsid", Getsid),
		125: syscalls.Supported("capget", Capget),
		126: syscalls.Supported("capset", Capset),
		127: syscalls.Supported("rt_sigpending", RtSigpending),
		128: syscalls.Supported("rt_sigtimedwait", RtSigtimedwait),
		129: syscalls.Supported("rt_sigqueueinfo", RtSigqueueinfo),
		130: syscalls.Supported("rt_sigsuspend", RtSigsuspend),
		131: syscalls.Supported("sigaltstack", Sigaltstack),
		132: syscalls.Supported("utime", Utime),
		133: syscalls.PartiallySupported("mknod", Mknod, "Device creation is not generally supported. Only regular file and FIFO creation are supported.", nil),
		134: syscalls.Error("uselib", syserror.ENOSYS, "Obsolete", nil),
		135: syscalls.ErrorWithEvent("personality", syserror.EINVAL, "Unable to change personality.", nil),
		136: syscalls.ErrorWithEvent("ustat", syserror.ENOSYS, "Needs filesystem support.", nil),
		137: syscalls.PartiallySupported("statfs", Statfs, "Depends on the backing file system implementation.", nil),
		138: syscalls.PartiallySupported("fstatfs", Fstatfs, "Depends on the backing file system implementation.", nil),
		139: syscalls.ErrorWithEvent("sysfs", syserror.ENOSYS, "", []string{"gvisor.dev/issue/165"}),
		140: syscalls.PartiallySupported("getpriority", Getpriority, "Stub implementation.", nil),
		141: syscalls.PartiallySupported("setpriority", Setpriority, "Stub implementation.", nil),
		142: syscalls.CapError("sched_setparam", linux.CAP_SYS_NICE, "", nil),
		143: syscalls.PartiallySupported("sched_getparam", SchedGetparam, "Stub implementation.", nil),
		144: syscalls.PartiallySupported("sched_setscheduler", SchedSetscheduler, "Stub implementation.", nil),
		145: syscalls.PartiallySupported("sched_getscheduler", SchedGetscheduler, "Stub implementation.", nil),
		146: syscalls.PartiallySupported("sched_get_priority_max", SchedGetPriorityMax, "Stub implementation.", nil),
		147: syscalls.PartiallySupported("sched_get_priority_min", SchedGetPriorityMin, "Stub implementation.", nil),
		148: syscalls.ErrorWithEvent("sched_rr_get_interval", syserror.EPERM, "", nil),
		149: syscalls.PartiallySupported("mlock", Mlock, "Stub implementation. The sandbox lacks appropriate permissions.", nil),
		150: syscalls.PartiallySupported("munlock", Munlock, "Stub implementation. The sandbox lacks appropriate permissions.", nil),
		151: syscalls.PartiallySupported("mlockall", Mlockall, "Stub implementation. The sandbox lacks appropriate permissions.", nil),
		152: syscalls.PartiallySupported("munlockall", Munlockall, "Stub implementation. The sandbox lacks appropriate permissions.", nil),
		153: syscalls.CapError("vhangup", linux.CAP_SYS_TTY_CONFIG, "", nil),
		154: syscalls.Error("modify_ldt", syserror.EPERM, "", nil),
		155: syscalls.Error("pivot_root", syserror.EPERM, "", nil),
		156: syscalls.Error("sysctl", syserror.EPERM, "Deprecated. Use /proc/sys instead.", nil),
		157: syscalls.PartiallySupported("prctl", Prctl, "Not all options are supported.", nil),
		158: syscalls.PartiallySupported("arch_prctl", ArchPrctl, "Options ARCH_GET_GS, ARCH_SET_GS not supported.", nil),
		159: syscalls.CapError("adjtimex", linux.CAP_SYS_TIME, "", nil),
		160: syscalls.PartiallySupported("setrlimit", Setrlimit, "Not all rlimits are enforced.", nil),
		161: syscalls.Supported("chroot", Chroot),
		162: syscalls.PartiallySupported("sync", Sync, "Full data flush is not guaranteed at this time.", nil),
		163: syscalls.CapError("acct", linux.CAP_SYS_PACCT, "", nil),
		164: syscalls.CapError("settimeofday", linux.CAP_SYS_TIME, "", nil),
		165: syscalls.PartiallySupported("mount", Mount, "Not all options or file systems are supported.", nil),
		166: syscalls.PartiallySupported("umount2", Umount2, "Not all options or file systems are supported.", nil),
		167: syscalls.CapError("swapon", linux.CAP_SYS_ADMIN, "", nil),
		168: syscalls.CapError("swapoff", linux.CAP_SYS_ADMIN, "", nil),
		169: syscalls.CapError("reboot", linux.CAP_SYS_BOOT, "", nil),
		170: syscalls.Supported("sethostname", Sethostname),
		171: syscalls.Supported("setdomainname", Setdomainname),
		172: syscalls.CapError("iopl", linux.CAP_SYS_RAWIO, "", nil),
		173: syscalls.CapError("ioperm", linux.CAP_SYS_RAWIO, "", nil),
		174: syscalls.CapError("create_module", linux.CAP_SYS_MODULE, "", nil),
		175: syscalls.CapError("init_module", linux.CAP_SYS_MODULE, "", nil),
		176: syscalls.CapError("delete_module", linux.CAP_SYS_MODULE, "", nil),
		177: syscalls.Error("get_kernel_syms", syserror.ENOSYS, "Not supported in Linux > 2.6.", nil),
		178: syscalls.Error("query_module", syserror.ENOSYS, "Not supported in Linux > 2.6.", nil),
		179: syscalls.CapError("quotactl", linux.CAP_SYS_ADMIN, "", nil), // requires cap_sys_admin for most operations
		180: syscalls.Error("nfsservctl", syserror.ENOSYS, "Removed after Linux 3.1.", nil),
		181: syscalls.Error("getpmsg", syserror.ENOSYS, "Not implemented in Linux.", nil),
		182: syscalls.Error("putpmsg", syserror.ENOSYS, "Not implemented in Linux.", nil),
		183: syscalls.Error("afs_syscall", syserror.ENOSYS, "Not implemented in Linux.", nil),
		184: syscalls.Error("tuxcall", syserror.ENOSYS, "Not implemented in Linux.", nil),
		185: syscalls.Error("security", syserror.ENOSYS, "Not implemented in Linux.", nil),
		186: syscalls.Supported("gettid", Gettid),
		187: syscalls.ErrorWithEvent("readahead", syserror.ENOSYS, "", []string{"gvisor.dev/issue/261"}), // TODO(b/29351341)
		188: syscalls.Error("setxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		189: syscalls.Error("lsetxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		190: syscalls.Error("fsetxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		191: syscalls.ErrorWithEvent("getxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		192: syscalls.ErrorWithEvent("lgetxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		193: syscalls.ErrorWithEvent("fgetxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		194: syscalls.ErrorWithEvent("listxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		195: syscalls.ErrorWithEvent("llistxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		196: syscalls.ErrorWithEvent("flistxattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		197: syscalls.ErrorWithEvent("removexattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		198: syscalls.ErrorWithEvent("lremovexattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		199: syscalls.ErrorWithEvent("fremovexattr", syserror.ENOTSUP, "Requires filesystem support.", nil),
		200: syscalls.Supported("tkill", Tkill),
		201: syscalls.Supported("time", Time),
		202: syscalls.PartiallySupported("futex", Futex, "Robust futexes not supported.", nil),
		203: syscalls.PartiallySupported("sched_setaffinity", SchedSetaffinity, "Stub implementation.", nil),
		204: syscalls.PartiallySupported("sched_getaffinity", SchedGetaffinity, "Stub implementation.", nil),
		205: syscalls.Error("set_thread_area", syserror.ENOSYS, "Expected to return ENOSYS on 64-bit", nil),
		206: syscalls.PartiallySupported("io_setup", IoSetup, "Generally supported with exceptions. User ring optimizations are not implemented.", []string{"gvisor.dev/issue/204"}),
		207: syscalls.PartiallySupported("io_destroy", IoDestroy, "Generally supported with exceptions. User ring optimizations are not implemented.", []string{"gvisor.dev/issue/204"}),
		208: syscalls.PartiallySupported("io_getevents", IoGetevents, "Generally supported with exceptions. User ring optimizations are not implemented.", []string{"gvisor.dev/issue/204"}),
		209: syscalls.PartiallySupported("io_submit", IoSubmit, "Generally supported with exceptions. User ring optimizations are not implemented.", []string{"gvisor.dev/issue/204"}),
		210: syscalls.PartiallySupported("io_cancel", IoCancel, "Generally supported with exceptions. User ring optimizations are not implemented.", []string{"gvisor.dev/issue/204"}),
		211: syscalls.Error("get_thread_area", syserror.ENOSYS, "Expected to return ENOSYS on 64-bit", nil),
		212: syscalls.CapError("lookup_dcookie", linux.CAP_SYS_ADMIN, "", nil),
		213: syscalls.Supported("epoll_create", EpollCreate),
		214: syscalls.ErrorWithEvent("epoll_ctl_old", syserror.ENOSYS, "Deprecated.", nil),
		215: syscalls.ErrorWithEvent("epoll_wait_old", syserror.ENOSYS, "Deprecated.", nil),
		216: syscalls.ErrorWithEvent("remap_file_pages", syserror.ENOSYS, "Deprecated since Linux 3.16.", nil),
		217: syscalls.Supported("getdents64", Getdents64),
		218: syscalls.Supported("set_tid_address", SetTidAddress),
		219: syscalls.Supported("restart_syscall", RestartSyscall),
		220: syscalls.ErrorWithEvent("semtimedop", syserror.ENOSYS, "", []string{"gvisor.dev/issue/137"}), // TODO(b/29354920)
		221: syscalls.PartiallySupported("fadvise64", Fadvise64, "Not all options are supported.", nil),
		222: syscalls.Supported("timer_create", TimerCreate),
		223: syscalls.Supported("timer_settime", TimerSettime),
		224: syscalls.Supported("timer_gettime", TimerGettime),
		225: syscalls.Supported("timer_getoverrun", TimerGetoverrun),
		226: syscalls.Supported("timer_delete", TimerDelete),
		227: syscalls.Supported("clock_settime", ClockSettime),
		228: syscalls.Supported("clock_gettime", ClockGettime),
		229: syscalls.Supported("clock_getres", ClockGetres),
		230: syscalls.Supported("clock_nanosleep", ClockNanosleep),
		231: syscalls.Supported("exit_group", ExitGroup),
		232: syscalls.Supported("epoll_wait", EpollWait),
		233: syscalls.Supported("epoll_ctl", EpollCtl),
		234: syscalls.Supported("tgkill", Tgkill),
		235: syscalls.Supported("utimes", Utimes),
		236: syscalls.Error("vserver", syserror.ENOSYS, "Not implemented by Linux", nil),
		237: syscalls.PartiallySupported("mbind", Mbind, "Stub implementation. Only a single NUMA node is advertised, and mempolicy is ignored accordingly, but mbind() will succeed and has effects reflected by get_mempolicy.", []string{"gvisor.dev/issue/262"}),
		238: syscalls.PartiallySupported("set_mempolicy", SetMempolicy, "Stub implementation.", nil),
		239: syscalls.PartiallySupported("get_mempolicy", GetMempolicy, "Stub implementation.", nil),
		240: syscalls.ErrorWithEvent("mq_open", syserror.ENOSYS, "", []string{"gvisor.dev/issue/136"}),         // TODO(b/29354921)
		241: syscalls.ErrorWithEvent("mq_unlink", syserror.ENOSYS, "", []string{"gvisor.dev/issue/136"}),       // TODO(b/29354921)
		242: syscalls.ErrorWithEvent("mq_timedsend", syserror.ENOSYS, "", []string{"gvisor.dev/issue/136"}),    // TODO(b/29354921)
		243: syscalls.ErrorWithEvent("mq_timedreceive", syserror.ENOSYS, "", []string{"gvisor.dev/issue/136"}), // TODO(b/29354921)
		244: syscalls.ErrorWithEvent("mq_notify", syserror.ENOSYS, "", []string{"gvisor.dev/issue/136"}),       // TODO(b/29354921)
		245: syscalls.ErrorWithEvent("mq_getsetattr", syserror.ENOSYS, "", []string{"gvisor.dev/issue/136"}),   // TODO(b/29354921)
		246: syscalls.CapError("kexec_load", linux.CAP_SYS_BOOT, "", nil),
		247: syscalls.Supported("waitid", Waitid),
		248: syscalls.Error("add_key", syserror.EACCES, "Not available to user.", nil),
		249: syscalls.Error("request_key", syserror.EACCES, "Not available to user.", nil),
		250: syscalls.Error("keyctl", syserror.EACCES, "Not available to user.", nil),
		251: syscalls.CapError("ioprio_set", linux.CAP_SYS_ADMIN, "", nil), // requires cap_sys_nice or cap_sys_admin (depending)
		252: syscalls.CapError("ioprio_get", linux.CAP_SYS_ADMIN, "", nil), // requires cap_sys_nice or cap_sys_admin (depending)
		253: syscalls.PartiallySupported("inotify_init", InotifyInit, "inotify events are only available inside the sandbox.", nil),
		254: syscalls.PartiallySupported("inotify_add_watch", InotifyAddWatch, "inotify events are only available inside the sandbox.", nil),
		255: syscalls.PartiallySupported("inotify_rm_watch", InotifyRmWatch, "inotify events are only available inside the sandbox.", nil),
		256: syscalls.CapError("migrate_pages", linux.CAP_SYS_NICE, "", nil),
		257: syscalls.Supported("openat", Openat),
		258: syscalls.Supported("mkdirat", Mkdirat),
		259: syscalls.Supported("mknodat", Mknodat),
		260: syscalls.Supported("fchownat", Fchownat),
		261: syscalls.Supported("futimesat", Futimesat),
		262: syscalls.Supported("fstatat", Fstatat),
		263: syscalls.Supported("unlinkat", Unlinkat),
		264: syscalls.Supported("renameat", Renameat),
		265: syscalls.Supported("linkat", Linkat),
		266: syscalls.Supported("symlinkat", Symlinkat),
		267: syscalls.Supported("readlinkat", Readlinkat),
		268: syscalls.Supported("fchmodat", Fchmodat),
		269: syscalls.Supported("faccessat", Faccessat),
		270: syscalls.Supported("pselect", Pselect),
		271: syscalls.Supported("ppoll", Ppoll),
		272: syscalls.PartiallySupported("unshare", Unshare, "Mount, cgroup namespaces not supported. Network namespaces supported but must be empty.", nil),
		273: syscalls.Error("set_robust_list", syserror.ENOSYS, "Obsolete.", nil),
		274: syscalls.Error("get_robust_list", syserror.ENOSYS, "Obsolete.", nil),
		275: syscalls.PartiallySupported("splice", Splice, "Stub implementation.", []string{"gvisor.dev/issue/138"}), // TODO(b/29354098)
		276: syscalls.ErrorWithEvent("tee", syserror.ENOSYS, "", []string{"gvisor.dev/issue/138"}),                   // TODO(b/29354098)
		277: syscalls.PartiallySupported("sync_file_range", SyncFileRange, "Full data flush is not guaranteed at this time.", nil),
		278: syscalls.ErrorWithEvent("vmsplice", syserror.ENOSYS, "", []string{"gvisor.dev/issue/138"}), // TODO(b/29354098)
		279: syscalls.CapError("move_pages", linux.CAP_SYS_NICE, "", nil),                               // requires cap_sys_nice (mostly)
		280: syscalls.Supported("utimensat", Utimensat),
		281: syscalls.Supported("epoll_pwait", EpollPwait),
		282: syscalls.ErrorWithEvent("signalfd", syserror.ENOSYS, "", []string{"gvisor.dev/issue/139"}), // TODO(b/19846426)
		283: syscalls.Supported("timerfd_create", TimerfdCreate),
		284: syscalls.Supported("eventfd", Eventfd),
		285: syscalls.PartiallySupported("fallocate", Fallocate, "Not all options are supported.", nil),
		286: syscalls.Supported("timerfd_settime", TimerfdSettime),
		287: syscalls.Supported("timerfd_gettime", TimerfdGettime),
		288: syscalls.Supported("accept4", Accept4),
		289: syscalls.ErrorWithEvent("signalfd4", syserror.ENOSYS, "", []string{"gvisor.dev/issue/139"}), // TODO(b/19846426)
		290: syscalls.Supported("eventfd2", Eventfd2),
		291: syscalls.Supported("epoll_create1", EpollCreate1),
		292: syscalls.Supported("dup3", Dup3),
		293: syscalls.Supported("pipe2", Pipe2),
		294: syscalls.Supported("inotify_init1", InotifyInit1),
		295: syscalls.Supported("preadv", Preadv),
		296: syscalls.Supported("pwritev", Pwritev),
		297: syscalls.Supported("rt_tgsigqueueinfo", RtTgsigqueueinfo),
		298: syscalls.ErrorWithEvent("perf_event_open", syserror.ENODEV, "No support for perf counters", nil),
		299: syscalls.PartiallySupported("recvmmsg", RecvMMsg, "Not all flags and control messages are supported.", nil),
		300: syscalls.ErrorWithEvent("fanotify_init", syserror.ENOSYS, "Needs CONFIG_FANOTIFY", nil),
		301: syscalls.ErrorWithEvent("fanotify_mark", syserror.ENOSYS, "Needs CONFIG_FANOTIFY", nil),
		302: syscalls.Supported("prlimit64", Prlimit64),
		303: syscalls.Error("name_to_handle_at", syserror.EOPNOTSUPP, "Not supported by gVisor filesystems", nil),
		304: syscalls.Error("open_by_handle_at", syserror.EOPNOTSUPP, "Not supported by gVisor filesystems", nil),
		305: syscalls.CapError("clock_adjtime", linux.CAP_SYS_TIME, "", nil),
		306: syscalls.PartiallySupported("syncfs", Syncfs, "Depends on backing file system.", nil),
		307: syscalls.PartiallySupported("sendmmsg", SendMMsg, "Not all flags and control messages are supported.", nil),
		308: syscalls.ErrorWithEvent("setns", syserror.EOPNOTSUPP, "Needs filesystem support", []string{"gvisor.dev/issue/140"}), // TODO(b/29354995)
		309: syscalls.Supported("getcpu", Getcpu),
		310: syscalls.ErrorWithEvent("process_vm_readv", syserror.ENOSYS, "", []string{"gvisor.dev/issue/158"}),
		311: syscalls.ErrorWithEvent("process_vm_writev", syserror.ENOSYS, "", []string{"gvisor.dev/issue/158"}),
		312: syscalls.CapError("kcmp", linux.CAP_SYS_PTRACE, "", nil),
		313: syscalls.CapError("finit_module", linux.CAP_SYS_MODULE, "", nil),
		314: syscalls.ErrorWithEvent("sched_setattr", syserror.ENOSYS, "gVisor does not implement a scheduler.", []string{"gvisor.dev/issue/264"}), // TODO(b/118902272)
		315: syscalls.ErrorWithEvent("sched_getattr", syserror.ENOSYS, "gVisor does not implement a scheduler.", []string{"gvisor.dev/issue/264"}), // TODO(b/118902272)
		316: syscalls.ErrorWithEvent("renameat2", syserror.ENOSYS, "", []string{"gvisor.dev/issue/263"}),                                           // TODO(b/118902772)
		317: syscalls.Supported("seccomp", Seccomp),
		318: syscalls.Supported("getrandom", GetRandom),
		319: syscalls.Supported("memfd_create", MemfdCreate),
		320: syscalls.CapError("kexec_file_load", linux.CAP_SYS_BOOT, "", nil),
		321: syscalls.CapError("bpf", linux.CAP_SYS_ADMIN, "", nil),
		322: syscalls.ErrorWithEvent("execveat", syserror.ENOSYS, "", []string{"gvisor.dev/issue/265"}),    // TODO(b/118901836)
		323: syscalls.ErrorWithEvent("userfaultfd", syserror.ENOSYS, "", []string{"gvisor.dev/issue/266"}), // TODO(b/118906345)
		324: syscalls.ErrorWithEvent("membarrier", syserror.ENOSYS, "", []string{"gvisor.dev/issue/267"}),  // TODO(b/118904897)
		325: syscalls.PartiallySupported("mlock2", Mlock2, "Stub implementation. The sandbox lacks appropriate permissions.", nil),

		// Syscalls after 325 are "backports" from versions of Linux after 4.4.
		326: syscalls.ErrorWithEvent("copy_file_range", syserror.ENOSYS, "", nil),
		327: syscalls.Supported("preadv2", Preadv2),
		328: syscalls.PartiallySupported("pwritev2", Pwritev2, "Flag RWF_HIPRI is not supported.", nil),
		332: syscalls.Supported("statx", Statx),
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
