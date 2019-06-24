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
	"syscall"

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
		2:   syscalls.Supported("open", Open),
		3:   syscalls.Supported("close", Close),
		4:   syscalls.Undocumented("stat", Stat),
		5:   syscalls.Undocumented("fstat", Fstat),
		6:   syscalls.Undocumented("lstat", Lstat),
		7:   syscalls.Undocumented("poll", Poll),
		8:   syscalls.Undocumented("lseek", Lseek),
		9:   syscalls.Undocumented("mmap", Mmap),
		10:  syscalls.Undocumented("mprotect", Mprotect),
		11:  syscalls.Undocumented("munmap", Munmap),
		12:  syscalls.Undocumented("brk", Brk),
		13:  syscalls.Undocumented("rt_sigaction", RtSigaction),
		14:  syscalls.Undocumented("rt_sigprocmask", RtSigprocmask),
		15:  syscalls.Undocumented("rt_sigreturn", RtSigreturn),
		16:  syscalls.Undocumented("ioctl", Ioctl),
		17:  syscalls.Undocumented("pread64", Pread64),
		18:  syscalls.Undocumented("pwrite64", Pwrite64),
		19:  syscalls.Undocumented("readv", Readv),
		20:  syscalls.Undocumented("writev", Writev),
		21:  syscalls.Undocumented("access", Access),
		22:  syscalls.Undocumented("pipe", Pipe),
		23:  syscalls.Undocumented("select", Select),
		24:  syscalls.Undocumented("sched_yield", SchedYield),
		25:  syscalls.Undocumented("mremap", Mremap),
		26:  syscalls.Undocumented("msync", Msync),
		27:  syscalls.Undocumented("mincore", Mincore),
		28:  syscalls.Undocumented("madvise", Madvise),
		29:  syscalls.Undocumented("shmget", Shmget),
		30:  syscalls.Undocumented("shmat", Shmat),
		31:  syscalls.Undocumented("shmctl", Shmctl),
		32:  syscalls.Undocumented("dup", Dup),
		33:  syscalls.Undocumented("dup2", Dup2),
		34:  syscalls.Undocumented("pause", Pause),
		35:  syscalls.Undocumented("nanosleep", Nanosleep),
		36:  syscalls.Undocumented("getitimer", Getitimer),
		37:  syscalls.Undocumented("alarm", Alarm),
		38:  syscalls.Undocumented("setitimer", Setitimer),
		39:  syscalls.Undocumented("getpid", Getpid),
		40:  syscalls.Undocumented("sendfile", Sendfile),
		41:  syscalls.Undocumented("socket", Socket),
		42:  syscalls.Undocumented("connect", Connect),
		43:  syscalls.Undocumented("accept", Accept),
		44:  syscalls.Undocumented("sendto", SendTo),
		45:  syscalls.Undocumented("recvfrom", RecvFrom),
		46:  syscalls.Undocumented("sendmsg", SendMsg),
		47:  syscalls.Undocumented("recvmsg", RecvMsg),
		48:  syscalls.Undocumented("shutdown", Shutdown),
		49:  syscalls.Undocumented("bind", Bind),
		50:  syscalls.Undocumented("listen", Listen),
		51:  syscalls.Undocumented("getsockname", GetSockName),
		52:  syscalls.Undocumented("getpeername", GetPeerName),
		53:  syscalls.Undocumented("socketpair", SocketPair),
		54:  syscalls.Undocumented("setsockopt", SetSockOpt),
		55:  syscalls.Undocumented("getsockopt", GetSockOpt),
		56:  syscalls.Undocumented("clone", Clone),
		57:  syscalls.Undocumented("fork", Fork),
		58:  syscalls.Undocumented("vfork", Vfork),
		59:  syscalls.Undocumented("execve", Execve),
		60:  syscalls.Undocumented("exit", Exit),
		61:  syscalls.Undocumented("wait4", Wait4),
		62:  syscalls.Undocumented("kill", Kill),
		63:  syscalls.Undocumented("uname", Uname),
		64:  syscalls.Undocumented("semget", Semget),
		65:  syscalls.Undocumented("semop", Semop),
		66:  syscalls.Undocumented("semctl", Semctl),
		67:  syscalls.Undocumented("shmdt", Shmdt),
		68:  syscalls.ErrorWithEvent("msgget", syscall.ENOSYS, "", []string{"gvisor.dev/issue/135"}), // TODO(b/29354921)
		69:  syscalls.ErrorWithEvent("msgsnd", syscall.ENOSYS, "", []string{"gvisor.dev/issue/135"}), // TODO(b/29354921)
		70:  syscalls.ErrorWithEvent("msgrcv", syscall.ENOSYS, "", []string{"gvisor.dev/issue/135"}), // TODO(b/29354921)
		71:  syscalls.ErrorWithEvent("msgctl", syscall.ENOSYS, "", []string{"gvisor.dev/issue/135"}), // TODO(b/29354921)
		72:  syscalls.Undocumented("fcntl", Fcntl),
		73:  syscalls.Undocumented("flock", Flock),
		74:  syscalls.Undocumented("fsync", Fsync),
		75:  syscalls.Undocumented("fdatasync", Fdatasync),
		76:  syscalls.Undocumented("truncate", Truncate),
		77:  syscalls.Undocumented("ftruncate", Ftruncate),
		78:  syscalls.Undocumented("getdents", Getdents),
		79:  syscalls.Undocumented("getcwd", Getcwd),
		80:  syscalls.Undocumented("chdir", Chdir),
		81:  syscalls.Undocumented("fchdir", Fchdir),
		82:  syscalls.Undocumented("rename", Rename),
		83:  syscalls.Undocumented("mkdir", Mkdir),
		84:  syscalls.Undocumented("rmdir", Rmdir),
		85:  syscalls.Undocumented("creat", Creat),
		86:  syscalls.Undocumented("link", Link),
		87:  syscalls.Undocumented("link", Unlink),
		88:  syscalls.Undocumented("symlink", Symlink),
		89:  syscalls.Undocumented("readlink", Readlink),
		90:  syscalls.Undocumented("chmod", Chmod),
		91:  syscalls.Undocumented("fchmod", Fchmod),
		92:  syscalls.Undocumented("chown", Chown),
		93:  syscalls.Undocumented("fchown", Fchown),
		94:  syscalls.Undocumented("lchown", Lchown),
		95:  syscalls.Undocumented("umask", Umask),
		96:  syscalls.Undocumented("gettimeofday", Gettimeofday),
		97:  syscalls.Undocumented("getrlimit", Getrlimit),
		98:  syscalls.Undocumented("getrusage", Getrusage),
		99:  syscalls.Undocumented("sysinfo", Sysinfo),
		100: syscalls.Undocumented("times", Times),
		101: syscalls.Undocumented("ptrace", Ptrace),
		102: syscalls.Undocumented("getuid", Getuid),
		103: syscalls.Undocumented("syslog", Syslog),
		104: syscalls.Undocumented("getgid", Getgid),
		105: syscalls.Undocumented("setuid", Setuid),
		106: syscalls.Undocumented("setgid", Setgid),
		107: syscalls.Undocumented("geteuid", Geteuid),
		108: syscalls.Undocumented("getegid", Getegid),
		109: syscalls.Undocumented("setpgid", Setpgid),
		110: syscalls.Undocumented("getppid", Getppid),
		111: syscalls.Undocumented("getpgrp", Getpgrp),
		112: syscalls.Undocumented("setsid", Setsid),
		113: syscalls.Undocumented("setreuid", Setreuid),
		114: syscalls.Undocumented("setregid", Setregid),
		115: syscalls.Undocumented("getgroups", Getgroups),
		116: syscalls.Undocumented("setgroups", Setgroups),
		117: syscalls.Undocumented("setresuid", Setresuid),
		118: syscalls.Undocumented("getresuid", Getresuid),
		119: syscalls.Undocumented("setresgid", Setresgid),
		120: syscalls.Undocumented("setresgid", Getresgid),
		121: syscalls.Undocumented("getpgid", Getpgid),
		122: syscalls.ErrorWithEvent("setfsuid", syscall.ENOSYS, "", []string{"gvisor.dev/issue/260"}), // TODO(b/112851702)
		123: syscalls.ErrorWithEvent("setfsgid", syscall.ENOSYS, "", []string{"gvisor.dev/issue/260"}), // TODO(b/112851702)
		124: syscalls.Undocumented("getsid", Getsid),
		125: syscalls.Undocumented("capget", Capget),
		126: syscalls.Undocumented("capset", Capset),
		127: syscalls.Undocumented("rt_sigpending", RtSigpending),
		128: syscalls.Undocumented("rt_sigtimedwait", RtSigtimedwait),
		129: syscalls.Undocumented("rt_sigqueueinfo", RtSigqueueinfo),
		130: syscalls.Undocumented("rt_sigsuspend", RtSigsuspend),
		131: syscalls.Undocumented("sigaltstack", Sigaltstack),
		132: syscalls.Undocumented("utime", Utime),
		133: syscalls.Undocumented("mknod", Mknod),
		134: syscalls.Error("uselib", syscall.ENOSYS, "Obsolete", nil),
		135: syscalls.ErrorWithEvent("personality", syscall.EINVAL, "Unable to change personality.", nil),
		136: syscalls.ErrorWithEvent("ustat", syscall.ENOSYS, "Needs filesystem support.", nil),
		137: syscalls.Undocumented("statfs", Statfs),
		138: syscalls.Undocumented("fstatfs", Fstatfs),
		139: syscalls.ErrorWithEvent("sysfs", syscall.ENOSYS, "", []string{"gvisor.dev/issue/165"}),
		140: syscalls.Undocumented("getpriority", Getpriority),
		141: syscalls.Undocumented("setpriority", Setpriority),
		142: syscalls.CapError("sched_setparam", linux.CAP_SYS_NICE, "", nil),
		143: syscalls.Undocumented("sched_getparam", SchedGetparam),
		144: syscalls.Undocumented("sched_setscheduler", SchedSetscheduler),
		145: syscalls.Undocumented("sched_getscheduler", SchedGetscheduler),
		146: syscalls.Undocumented("sched_get_priority_max", SchedGetPriorityMax),
		147: syscalls.Undocumented("sched_get_priority_min", SchedGetPriorityMin),
		148: syscalls.ErrorWithEvent("sched_rr_get_interval", syscall.EPERM, "", nil),
		149: syscalls.Undocumented("mlock", Mlock),
		150: syscalls.Undocumented("munlock", Munlock),
		151: syscalls.Undocumented("mlockall", Mlockall),
		152: syscalls.Undocumented("munlockall", Munlockall),
		153: syscalls.CapError("vhangup", linux.CAP_SYS_TTY_CONFIG, "", nil),
		154: syscalls.Error("modify_ldt", syscall.EPERM, "", nil),
		155: syscalls.Error("pivot_root", syscall.EPERM, "", nil),
		156: syscalls.Error("sysctl", syscall.EPERM, `syscall is "worthless"`, nil),
		157: syscalls.Undocumented("prctl", Prctl),
		158: syscalls.Undocumented("arch_prctl", ArchPrctl),
		159: syscalls.CapError("adjtimex", linux.CAP_SYS_TIME, "", nil),
		160: syscalls.Undocumented("setrlimit", Setrlimit),
		161: syscalls.Undocumented("chroot", Chroot),
		162: syscalls.Undocumented("sync", Sync),
		163: syscalls.CapError("acct", linux.CAP_SYS_PACCT, "", nil),
		164: syscalls.CapError("settimeofday", linux.CAP_SYS_TIME, "", nil),
		165: syscalls.Undocumented("mount", Mount),
		166: syscalls.Undocumented("umount2", Umount2),
		167: syscalls.CapError("swapon", linux.CAP_SYS_ADMIN, "", nil),
		168: syscalls.CapError("swapoff", linux.CAP_SYS_ADMIN, "", nil),
		169: syscalls.CapError("reboot", linux.CAP_SYS_BOOT, "", nil),
		170: syscalls.Undocumented("sethostname", Sethostname),
		171: syscalls.Undocumented("setdomainname", Setdomainname),
		172: syscalls.CapError("iopl", linux.CAP_SYS_RAWIO, "", nil),
		173: syscalls.CapError("ioperm", linux.CAP_SYS_RAWIO, "", nil),
		174: syscalls.CapError("create_module", linux.CAP_SYS_MODULE, "", nil),
		175: syscalls.CapError("init_module", linux.CAP_SYS_MODULE, "", nil),
		176: syscalls.CapError("delete_module", linux.CAP_SYS_MODULE, "", nil),
		177: syscalls.Error("get_kernel_syms", syscall.ENOSYS, "Not supported in > 2.6", nil),
		178: syscalls.Error("query_module", syscall.ENOSYS, "Not supported in > 2.6", nil),
		179: syscalls.CapError("quotactl", linux.CAP_SYS_ADMIN, "", nil), // requires cap_sys_admin for most operations
		180: syscalls.Error("nfsservctl", syscall.ENOSYS, "Does not exist > 3.1", nil),
		181: syscalls.Error("getpmsg", syscall.ENOSYS, "Not implemented in Linux", nil),
		182: syscalls.Error("putpmsg", syscall.ENOSYS, "Not implemented in Linux", nil),
		183: syscalls.Error("afs_syscall", syscall.ENOSYS, "Not implemented in Linux", nil),
		184: syscalls.Error("tuxcall", syscall.ENOSYS, "Not implemented in Linux", nil),
		185: syscalls.Error("security", syscall.ENOSYS, "Not implemented in Linux", nil),
		186: syscalls.Undocumented("gettid", Gettid),
		187: syscalls.ErrorWithEvent("readahead", syscall.ENOSYS, "", []string{"gvisor.dev/issue/261"}), // TODO(b/29351341)
		188: syscalls.ErrorWithEvent("setxattr", syscall.ENOTSUP, "Requires filesystem support", nil),
		189: syscalls.ErrorWithEvent("lsetxattr", syscall.ENOTSUP, "Requires filesystem support", nil),
		190: syscalls.ErrorWithEvent("fsetxattr", syscall.ENOTSUP, "Requires filesystem support", nil),
		191: syscalls.ErrorWithEvent("getxattr", syscall.ENOTSUP, "Requires filesystem support", nil),
		192: syscalls.ErrorWithEvent("lgetxattr", syscall.ENOTSUP, "Requires filesystem support", nil),
		193: syscalls.ErrorWithEvent("fgetxattr", syscall.ENOTSUP, "Requires filesystem support", nil),
		194: syscalls.ErrorWithEvent("listxattr", syscall.ENOTSUP, "Requires filesystem support", nil),
		195: syscalls.ErrorWithEvent("llistxattr", syscall.ENOTSUP, "Requires filesystem support", nil),
		196: syscalls.ErrorWithEvent("flistxattr", syscall.ENOTSUP, "Requires filesystem support", nil),
		197: syscalls.ErrorWithEvent("removexattr", syscall.ENOTSUP, "Requires filesystem support", nil),
		198: syscalls.ErrorWithEvent("lremovexattr", syscall.ENOTSUP, "Requires filesystem support", nil),
		199: syscalls.ErrorWithEvent("fremovexattr", syscall.ENOTSUP, "Requires filesystem support", nil),
		200: syscalls.Undocumented("tkill", Tkill),
		201: syscalls.Undocumented("time", Time),
		202: syscalls.Undocumented("futex", Futex),
		203: syscalls.Undocumented("sched_setaffinity", SchedSetaffinity),
		204: syscalls.Undocumented("sched_getaffinity", SchedGetaffinity),
		205: syscalls.Error("set_thread_area", syscall.ENOSYS, "Expected to return ENOSYS on 64-bit", nil),
		206: syscalls.Undocumented("io_setup", IoSetup),
		207: syscalls.Undocumented("io_destroy", IoDestroy),
		208: syscalls.Undocumented("io_getevents", IoGetevents),
		209: syscalls.Undocumented("io_submit", IoSubmit),
		210: syscalls.Undocumented("io_cancel", IoCancel),
		211: syscalls.Error("get_thread_area", syscall.ENOSYS, "Expected to return ENOSYS on 64-bit", nil),
		212: syscalls.CapError("lookup_dcookie", linux.CAP_SYS_ADMIN, "", nil),
		213: syscalls.Undocumented("epoll_create", EpollCreate),
		214: syscalls.ErrorWithEvent("epoll_ctl_old", syscall.ENOSYS, "Deprecated", nil),
		215: syscalls.ErrorWithEvent("epoll_wait_old", syscall.ENOSYS, "Deprecated", nil),
		216: syscalls.ErrorWithEvent("remap_file_pages", syscall.ENOSYS, "Deprecated since 3.16", nil),
		217: syscalls.Undocumented("getdents64", Getdents64),
		218: syscalls.Undocumented("set_tid_address", SetTidAddress),
		219: syscalls.Undocumented("restart_syscall", RestartSyscall),
		220: syscalls.ErrorWithEvent("semtimedop", syscall.ENOSYS, "", []string{"gvisor.dev/issue/137"}), // TODO(b/29354920)
		221: syscalls.Undocumented("fadvise64", Fadvise64),
		222: syscalls.Undocumented("timer_create", TimerCreate),
		223: syscalls.Undocumented("timer_settime", TimerSettime),
		224: syscalls.Undocumented("timer_gettime", TimerGettime),
		225: syscalls.Undocumented("timer_getoverrun", TimerGetoverrun),
		226: syscalls.Undocumented("timer_delete", TimerDelete),
		227: syscalls.Undocumented("clock_settime", ClockSettime),
		228: syscalls.Undocumented("clock_gettime", ClockGettime),
		229: syscalls.Undocumented("clock_getres", ClockGetres),
		230: syscalls.Undocumented("clock_nanosleep", ClockNanosleep),
		231: syscalls.Undocumented("exit_group", ExitGroup),
		232: syscalls.Undocumented("epoll_wait", EpollWait),
		233: syscalls.Undocumented("epoll_ctl", EpollCtl),
		234: syscalls.Undocumented("tgkill", Tgkill),
		235: syscalls.Undocumented("utimes", Utimes),
		236: syscalls.Error("vserver", syscall.ENOSYS, "Not implemented by Linux", nil),
		237: syscalls.PartiallySupported("mbind", Mbind, "Stub implementation. Only a single NUMA node is advertised, and mempolicy is ignored accordingly, but mbind() will succeed and has effects reflected by get_mempolicy.", []string{"gvisor.dev/issue/262"}),
		238: syscalls.Undocumented("set_mempolicy", SetMempolicy),
		239: syscalls.Undocumented("get_mempolicy", GetMempolicy),
		240: syscalls.ErrorWithEvent("mq_open", syscall.ENOSYS, "", []string{"gvisor.dev/issue/136"}),         // TODO(b/29354921)
		241: syscalls.ErrorWithEvent("mq_unlink", syscall.ENOSYS, "", []string{"gvisor.dev/issue/136"}),       // TODO(b/29354921)
		242: syscalls.ErrorWithEvent("mq_timedsend", syscall.ENOSYS, "", []string{"gvisor.dev/issue/136"}),    // TODO(b/29354921)
		243: syscalls.ErrorWithEvent("mq_timedreceive", syscall.ENOSYS, "", []string{"gvisor.dev/issue/136"}), // TODO(b/29354921)
		244: syscalls.ErrorWithEvent("mq_notify", syscall.ENOSYS, "", []string{"gvisor.dev/issue/136"}),       // TODO(b/29354921)
		245: syscalls.ErrorWithEvent("mq_getsetattr", syscall.ENOSYS, "", []string{"gvisor.dev/issue/136"}),   // TODO(b/29354921)
		246: syscalls.CapError("kexec_load", linux.CAP_SYS_BOOT, "", nil),
		247: syscalls.Undocumented("waitid", Waitid),
		248: syscalls.Error("add_key", syscall.EACCES, "Not available to user", nil),
		249: syscalls.Error("request_key", syscall.EACCES, "Not available to user", nil),
		250: syscalls.Error("keyctl", syscall.EACCES, "Not available to user", nil),
		251: syscalls.CapError("ioprio_set", linux.CAP_SYS_ADMIN, "", nil), // requires cap_sys_nice or cap_sys_admin (depending)
		252: syscalls.CapError("ioprio_get", linux.CAP_SYS_ADMIN, "", nil), // requires cap_sys_nice or cap_sys_admin (depending)
		253: syscalls.Undocumented("inotify_init", InotifyInit),
		254: syscalls.Undocumented("inotify_add_watch", InotifyAddWatch),
		255: syscalls.Undocumented("inotify_rm_watch", InotifyRmWatch),
		256: syscalls.CapError("migrate_pages", linux.CAP_SYS_NICE, "", nil),
		257: syscalls.Undocumented("openat", Openat),
		258: syscalls.Undocumented("mkdirat", Mkdirat),
		259: syscalls.Undocumented("mknodat", Mknodat),
		260: syscalls.Undocumented("fchownat", Fchownat),
		261: syscalls.Undocumented("futimesat", Futimesat),
		262: syscalls.Undocumented("fstatat", Fstatat),
		263: syscalls.Undocumented("unlinkat", Unlinkat),
		264: syscalls.Undocumented("renameat", Renameat),
		265: syscalls.Undocumented("linkat", Linkat),
		266: syscalls.Undocumented("symlinkat", Symlinkat),
		267: syscalls.Undocumented("readlinkat", Readlinkat),
		268: syscalls.Undocumented("fchmodat", Fchmodat),
		269: syscalls.Undocumented("faccessat", Faccessat),
		270: syscalls.Undocumented("pselect", Pselect),
		271: syscalls.Undocumented("ppoll", Ppoll),
		272: syscalls.Undocumented("unshare", Unshare),
		273: syscalls.Error("set_robust_list", syscall.ENOSYS, "Obsolete", nil),
		274: syscalls.Error("get_robust_list", syscall.ENOSYS, "Obsolete", nil),
		275: syscalls.PartiallySupported("splice", Splice, "Stub implementation", []string{"gvisor.dev/issue/138"}), // TODO(b/29354098)
		276: syscalls.ErrorWithEvent("tee", syscall.ENOSYS, "", []string{"gvisor.dev/issue/138"}),                   // TODO(b/29354098)
		277: syscalls.Undocumented("sync_file_range", SyncFileRange),
		278: syscalls.ErrorWithEvent("vmsplice", syscall.ENOSYS, "", []string{"gvisor.dev/issue/138"}), // TODO(b/29354098)
		279: syscalls.CapError("move_pages", linux.CAP_SYS_NICE, "", nil),                              // requires cap_sys_nice (mostly)
		280: syscalls.Undocumented("utimensat", Utimensat),
		281: syscalls.Undocumented("epoll_pwait", EpollPwait),
		282: syscalls.ErrorWithEvent("signalfd", syscall.ENOSYS, "", []string{"gvisor.dev/issue/139"}), // TODO(b/19846426)
		283: syscalls.Undocumented("timerfd_create", TimerfdCreate),
		284: syscalls.Undocumented("eventfd", Eventfd),
		285: syscalls.Undocumented("fallocate", Fallocate),
		286: syscalls.Undocumented("timerfd_settime", TimerfdSettime),
		287: syscalls.Undocumented("timerfd_gettime", TimerfdGettime),
		288: syscalls.Undocumented("accept4", Accept4),
		289: syscalls.ErrorWithEvent("signalfd4", syscall.ENOSYS, "", []string{"gvisor.dev/issue/139"}), // TODO(b/19846426)
		290: syscalls.Undocumented("eventfd2", Eventfd2),
		291: syscalls.Undocumented("epoll_create1", EpollCreate1),
		292: syscalls.Undocumented("dup3", Dup3),
		293: syscalls.Undocumented("pipe2", Pipe2),
		294: syscalls.Undocumented("inotify_init1", InotifyInit1),
		295: syscalls.Undocumented("preadv", Preadv),
		296: syscalls.Undocumented("pwritev", Pwritev),
		297: syscalls.Undocumented("rt_tgsigqueueinfo", RtTgsigqueueinfo),
		298: syscalls.ErrorWithEvent("perf_event_open", syscall.ENODEV, "No support for perf counters", nil),
		299: syscalls.Undocumented("recvmmsg", RecvMMsg),
		300: syscalls.ErrorWithEvent("fanotify_init", syscall.ENOSYS, "Needs CONFIG_FANOTIFY", nil),
		301: syscalls.ErrorWithEvent("fanotify_mark", syscall.ENOSYS, "Needs CONFIG_FANOTIFY", nil),
		302: syscalls.Undocumented("prlimit64", Prlimit64),
		303: syscalls.ErrorWithEvent("name_to_handle_at", syscall.EOPNOTSUPP, "Needs filesystem support", nil),
		304: syscalls.ErrorWithEvent("open_by_handle_at", syscall.EOPNOTSUPP, "Needs filesystem support", nil),
		305: syscalls.CapError("clock_adjtime", linux.CAP_SYS_TIME, "", nil),
		306: syscalls.Undocumented("syncfs", Syncfs),
		307: syscalls.Undocumented("sendmmsg", SendMMsg),
		308: syscalls.ErrorWithEvent("setns", syscall.EOPNOTSUPP, "Needs filesystem support", []string{"gvisor.dev/issue/140"}), // TODO(b/29354995)
		309: syscalls.Undocumented("getcpu", Getcpu),
		310: syscalls.ErrorWithEvent("process_vm_readv", syscall.ENOSYS, "", []string{"gvisor.dev/issue/158"}),
		311: syscalls.ErrorWithEvent("process_vm_writev", syscall.ENOSYS, "", []string{"gvisor.dev/issue/158"}),
		312: syscalls.CapError("kcmp", linux.CAP_SYS_PTRACE, "", nil),
		313: syscalls.CapError("finit_module", linux.CAP_SYS_MODULE, "", nil),
		314: syscalls.ErrorWithEvent("sched_setattr", syscall.ENOSYS, "gVisor does not implement a scheduler.", []string{"gvisor.dev/issue/264"}), // TODO(b/118902272)
		315: syscalls.ErrorWithEvent("sched_getattr", syscall.ENOSYS, "gVisor does not implement a scheduler.", []string{"gvisor.dev/issue/264"}), // TODO(b/118902272)
		316: syscalls.ErrorWithEvent("renameat2", syscall.ENOSYS, "", []string{"gvisor.dev/issue/263"}),                                           // TODO(b/118902772)
		317: syscalls.Undocumented("seccomp", Seccomp),
		318: syscalls.Undocumented("getrandom", GetRandom),
		319: syscalls.Undocumented("memfd_create", MemfdCreate),
		320: syscalls.CapError("kexec_file_load", linux.CAP_SYS_BOOT, "", nil),
		321: syscalls.CapError("bpf", linux.CAP_SYS_ADMIN, "", nil),
		322: syscalls.ErrorWithEvent("execveat", syscall.ENOSYS, "", []string{"gvisor.dev/issue/265"}),    // TODO(b/118901836)
		323: syscalls.ErrorWithEvent("userfaultfd", syscall.ENOSYS, "", []string{"gvisor.dev/issue/266"}), // TODO(b/118906345)
		324: syscalls.ErrorWithEvent("membarrier", syscall.ENOSYS, "", []string{"gvisor.dev/issue/267"}),  // TODO(b/118904897)
		325: syscalls.Undocumented("mlock2", Mlock2),

		// Syscalls after 325 are "backports" from versions of Linux after 4.4.
		326: syscalls.ErrorWithEvent("copy_file_range", syscall.ENOSYS, "", nil),
		327: syscalls.Undocumented("preadv2", Preadv2),
		328: syscalls.Undocumented("pwritev2", Pwritev2),
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
