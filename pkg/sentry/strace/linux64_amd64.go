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

// +build amd64

package strace

import (
	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// linuxAMD64 provides a mapping of the Linux amd64 syscalls and their argument
// types for display / formatting.
var linuxAMD64 = SyscallMap{
	0:   makeSyscallInfo("read", FD, ReadBuffer, Hex),
	1:   makeSyscallInfo("write", FD, WriteBuffer, Hex),
	2:   makeSyscallInfo("open", Path, OpenFlags, Mode),
	3:   makeSyscallInfo("close", FD),
	4:   makeSyscallInfo("stat", Path, Stat),
	5:   makeSyscallInfo("fstat", FD, Stat),
	6:   makeSyscallInfo("lstat", Path, Stat),
	7:   makeSyscallInfo("poll", PollFDs, Hex, Hex),
	8:   makeSyscallInfo("lseek", Hex, Hex, Hex),
	9:   makeSyscallInfo("mmap", Hex, Hex, Hex, Hex, FD, Hex),
	10:  makeSyscallInfo("mprotect", Hex, Hex, Hex),
	11:  makeSyscallInfo("munmap", Hex, Hex),
	12:  makeSyscallInfo("brk", Hex),
	13:  makeSyscallInfo("rt_sigaction", Signal, SigAction, PostSigAction, Hex),
	14:  makeSyscallInfo("rt_sigprocmask", SignalMaskAction, SigSet, PostSigSet, Hex),
	15:  makeSyscallInfo("rt_sigreturn"),
	16:  makeSyscallInfo("ioctl", FD, Hex, Hex),
	17:  makeSyscallInfo("pread64", FD, ReadBuffer, Hex, Hex),
	18:  makeSyscallInfo("pwrite64", FD, WriteBuffer, Hex, Hex),
	19:  makeSyscallInfo("readv", FD, ReadIOVec, Hex),
	20:  makeSyscallInfo("writev", FD, WriteIOVec, Hex),
	21:  makeSyscallInfo("access", Path, Oct),
	22:  makeSyscallInfo("pipe", PipeFDs),
	23:  makeSyscallInfo("select", Hex, SelectFDSet, SelectFDSet, SelectFDSet, Timeval),
	24:  makeSyscallInfo("sched_yield"),
	25:  makeSyscallInfo("mremap", Hex, Hex, Hex, Hex, Hex),
	26:  makeSyscallInfo("msync", Hex, Hex, Hex),
	27:  makeSyscallInfo("mincore", Hex, Hex, Hex),
	28:  makeSyscallInfo("madvise", Hex, Hex, Hex),
	29:  makeSyscallInfo("shmget", Hex, Hex, Hex),
	30:  makeSyscallInfo("shmat", Hex, Hex, Hex),
	31:  makeSyscallInfo("shmctl", Hex, Hex, Hex),
	32:  makeSyscallInfo("dup", FD),
	33:  makeSyscallInfo("dup2", FD, FD),
	34:  makeSyscallInfo("pause"),
	35:  makeSyscallInfo("nanosleep", Timespec, PostTimespec),
	36:  makeSyscallInfo("getitimer", ItimerType, PostItimerVal),
	37:  makeSyscallInfo("alarm", Hex),
	38:  makeSyscallInfo("setitimer", ItimerType, ItimerVal, PostItimerVal),
	39:  makeSyscallInfo("getpid"),
	40:  makeSyscallInfo("sendfile", FD, FD, Hex, Hex),
	41:  makeSyscallInfo("socket", SockFamily, SockType, SockProtocol),
	42:  makeSyscallInfo("connect", FD, SockAddr, Hex),
	43:  makeSyscallInfo("accept", FD, PostSockAddr, SockLen),
	44:  makeSyscallInfo("sendto", FD, Hex, Hex, Hex, SockAddr, Hex),
	45:  makeSyscallInfo("recvfrom", FD, Hex, Hex, Hex, PostSockAddr, SockLen),
	46:  makeSyscallInfo("sendmsg", FD, SendMsgHdr, Hex),
	47:  makeSyscallInfo("recvmsg", FD, RecvMsgHdr, Hex),
	48:  makeSyscallInfo("shutdown", FD, Hex),
	49:  makeSyscallInfo("bind", FD, SockAddr, Hex),
	50:  makeSyscallInfo("listen", FD, Hex),
	51:  makeSyscallInfo("getsockname", FD, PostSockAddr, SockLen),
	52:  makeSyscallInfo("getpeername", FD, PostSockAddr, SockLen),
	53:  makeSyscallInfo("socketpair", SockFamily, SockType, SockProtocol, Hex),
	54:  makeSyscallInfo("setsockopt", FD, SockOptLevel, SockOptName, SetSockOptVal, Hex /* length by value, not a pointer */),
	55:  makeSyscallInfo("getsockopt", FD, SockOptLevel, SockOptName, GetSockOptVal, SockLen),
	56:  makeSyscallInfo("clone", CloneFlags, Hex, Hex, Hex, Hex),
	57:  makeSyscallInfo("fork"),
	58:  makeSyscallInfo("vfork"),
	59:  makeSyscallInfo("execve", Path, ExecveStringVector, ExecveStringVector),
	60:  makeSyscallInfo("exit", Hex),
	61:  makeSyscallInfo("wait4", Hex, Hex, Hex, Rusage),
	62:  makeSyscallInfo("kill", Hex, Signal),
	63:  makeSyscallInfo("uname", Uname),
	64:  makeSyscallInfo("semget", Hex, Hex, Hex),
	65:  makeSyscallInfo("semop", Hex, Hex, Hex),
	66:  makeSyscallInfo("semctl", Hex, Hex, Hex, Hex),
	67:  makeSyscallInfo("shmdt", Hex),
	68:  makeSyscallInfo("msgget", Hex, Hex),
	69:  makeSyscallInfo("msgsnd", Hex, Hex, Hex, Hex),
	70:  makeSyscallInfo("msgrcv", Hex, Hex, Hex, Hex, Hex),
	71:  makeSyscallInfo("msgctl", Hex, Hex, Hex),
	72:  makeSyscallInfo("fcntl", FD, Hex, Hex),
	73:  makeSyscallInfo("flock", FD, Hex),
	74:  makeSyscallInfo("fsync", FD),
	75:  makeSyscallInfo("fdatasync", FD),
	76:  makeSyscallInfo("truncate", Path, Hex),
	77:  makeSyscallInfo("ftruncate", FD, Hex),
	78:  makeSyscallInfo("getdents", FD, Hex, Hex),
	79:  makeSyscallInfo("getcwd", PostPath, Hex),
	80:  makeSyscallInfo("chdir", Path),
	81:  makeSyscallInfo("fchdir", FD),
	82:  makeSyscallInfo("rename", Path, Path),
	83:  makeSyscallInfo("mkdir", Path, Oct),
	84:  makeSyscallInfo("rmdir", Path),
	85:  makeSyscallInfo("creat", Path, Oct),
	86:  makeSyscallInfo("link", Path, Path),
	87:  makeSyscallInfo("unlink", Path),
	88:  makeSyscallInfo("symlink", Path, Path),
	89:  makeSyscallInfo("readlink", Path, ReadBuffer, Hex),
	90:  makeSyscallInfo("chmod", Path, Mode),
	91:  makeSyscallInfo("fchmod", FD, Mode),
	92:  makeSyscallInfo("chown", Path, Hex, Hex),
	93:  makeSyscallInfo("fchown", FD, Hex, Hex),
	94:  makeSyscallInfo("lchown", Path, Hex, Hex),
	95:  makeSyscallInfo("umask", Hex),
	96:  makeSyscallInfo("gettimeofday", Timeval, Hex),
	97:  makeSyscallInfo("getrlimit", Hex, Hex),
	98:  makeSyscallInfo("getrusage", Hex, Rusage),
	99:  makeSyscallInfo("sysinfo", Hex),
	100: makeSyscallInfo("times", Hex),
	101: makeSyscallInfo("ptrace", PtraceRequest, Hex, Hex, Hex),
	102: makeSyscallInfo("getuid"),
	103: makeSyscallInfo("syslog", Hex, Hex, Hex),
	104: makeSyscallInfo("getgid"),
	105: makeSyscallInfo("setuid", Hex),
	106: makeSyscallInfo("setgid", Hex),
	107: makeSyscallInfo("geteuid"),
	108: makeSyscallInfo("getegid"),
	109: makeSyscallInfo("setpgid", Hex, Hex),
	110: makeSyscallInfo("getppid"),
	111: makeSyscallInfo("getpgrp"),
	112: makeSyscallInfo("setsid"),
	113: makeSyscallInfo("setreuid", Hex, Hex),
	114: makeSyscallInfo("setregid", Hex, Hex),
	115: makeSyscallInfo("getgroups", Hex, Hex),
	116: makeSyscallInfo("setgroups", Hex, Hex),
	117: makeSyscallInfo("setresuid", Hex, Hex, Hex),
	118: makeSyscallInfo("getresuid", Hex, Hex, Hex),
	119: makeSyscallInfo("setresgid", Hex, Hex, Hex),
	120: makeSyscallInfo("getresgid", Hex, Hex, Hex),
	121: makeSyscallInfo("getpgid", Hex),
	122: makeSyscallInfo("setfsuid", Hex),
	123: makeSyscallInfo("setfsgid", Hex),
	124: makeSyscallInfo("getsid", Hex),
	125: makeSyscallInfo("capget", CapHeader, PostCapData),
	126: makeSyscallInfo("capset", CapHeader, CapData),
	127: makeSyscallInfo("rt_sigpending", Hex),
	128: makeSyscallInfo("rt_sigtimedwait", SigSet, Hex, Timespec, Hex),
	129: makeSyscallInfo("rt_sigqueueinfo", Hex, Signal, Hex),
	130: makeSyscallInfo("rt_sigsuspend", Hex),
	131: makeSyscallInfo("sigaltstack", Hex, Hex),
	132: makeSyscallInfo("utime", Path, Utimbuf),
	133: makeSyscallInfo("mknod", Path, Mode, Hex),
	134: makeSyscallInfo("uselib", Hex),
	135: makeSyscallInfo("personality", Hex),
	136: makeSyscallInfo("ustat", Hex, Hex),
	137: makeSyscallInfo("statfs", Path, Hex),
	138: makeSyscallInfo("fstatfs", FD, Hex),
	139: makeSyscallInfo("sysfs", Hex, Hex, Hex),
	140: makeSyscallInfo("getpriority", Hex, Hex),
	141: makeSyscallInfo("setpriority", Hex, Hex, Hex),
	142: makeSyscallInfo("sched_setparam", Hex, Hex),
	143: makeSyscallInfo("sched_getparam", Hex, Hex),
	144: makeSyscallInfo("sched_setscheduler", Hex, Hex, Hex),
	145: makeSyscallInfo("sched_getscheduler", Hex),
	146: makeSyscallInfo("sched_get_priority_max", Hex),
	147: makeSyscallInfo("sched_get_priority_min", Hex),
	148: makeSyscallInfo("sched_rr_get_interval", Hex, Hex),
	149: makeSyscallInfo("mlock", Hex, Hex),
	150: makeSyscallInfo("munlock", Hex, Hex),
	151: makeSyscallInfo("mlockall", Hex),
	152: makeSyscallInfo("munlockall"),
	153: makeSyscallInfo("vhangup"),
	154: makeSyscallInfo("modify_ldt", Hex, Hex, Hex),
	155: makeSyscallInfo("pivot_root", Path, Path),
	156: makeSyscallInfo("_sysctl", Hex),
	157: makeSyscallInfo("prctl", Hex, Hex, Hex, Hex, Hex),
	158: makeSyscallInfo("arch_prctl", Hex, Hex),
	159: makeSyscallInfo("adjtimex", Hex),
	160: makeSyscallInfo("setrlimit", Hex, Hex),
	161: makeSyscallInfo("chroot", Path),
	162: makeSyscallInfo("sync"),
	163: makeSyscallInfo("acct", Hex),
	164: makeSyscallInfo("settimeofday", Timeval, Hex),
	165: makeSyscallInfo("mount", Path, Path, Path, Hex, Path),
	166: makeSyscallInfo("umount2", Path, Hex),
	167: makeSyscallInfo("swapon", Hex, Hex),
	168: makeSyscallInfo("swapoff", Hex),
	169: makeSyscallInfo("reboot", Hex, Hex, Hex, Hex),
	170: makeSyscallInfo("sethostname", Hex, Hex),
	171: makeSyscallInfo("setdomainname", Hex, Hex),
	172: makeSyscallInfo("iopl", Hex),
	173: makeSyscallInfo("ioperm", Hex, Hex, Hex),
	174: makeSyscallInfo("create_module", Path, Hex),
	175: makeSyscallInfo("init_module", Hex, Hex, Hex),
	176: makeSyscallInfo("delete_module", Hex, Hex),
	177: makeSyscallInfo("get_kernel_syms", Hex),
	// 178: query_module (only present in Linux < 2.6)
	179: makeSyscallInfo("quotactl", Hex, Hex, Hex, Hex),
	180: makeSyscallInfo("nfsservctl", Hex, Hex, Hex),
	// 181: getpmsg (not implemented in the Linux kernel)
	// 182: putpmsg (not implemented in the Linux kernel)
	// 183: afs_syscall (not implemented in the Linux kernel)
	// 184: tuxcall (not implemented in the Linux kernel)
	// 185: security (not implemented in the Linux kernel)
	186: makeSyscallInfo("gettid"),
	187: makeSyscallInfo("readahead", Hex, Hex, Hex),
	188: makeSyscallInfo("setxattr", Path, Path, Hex, Hex, Hex),
	189: makeSyscallInfo("lsetxattr", Path, Path, Hex, Hex, Hex),
	190: makeSyscallInfo("fsetxattr", FD, Path, Hex, Hex, Hex),
	191: makeSyscallInfo("getxattr", Path, Path, Hex, Hex),
	192: makeSyscallInfo("lgetxattr", Path, Path, Hex, Hex),
	193: makeSyscallInfo("fgetxattr", FD, Path, Hex, Hex),
	194: makeSyscallInfo("listxattr", Path, Path, Hex),
	195: makeSyscallInfo("llistxattr", Path, Path, Hex),
	196: makeSyscallInfo("flistxattr", FD, Path, Hex),
	197: makeSyscallInfo("removexattr", Path, Path),
	198: makeSyscallInfo("lremovexattr", Path, Path),
	199: makeSyscallInfo("fremovexattr", FD, Path),
	200: makeSyscallInfo("tkill", Hex, Signal),
	201: makeSyscallInfo("time", Hex),
	202: makeSyscallInfo("futex", Hex, FutexOp, Hex, Timespec, Hex, Hex),
	203: makeSyscallInfo("sched_setaffinity", Hex, Hex, Hex),
	204: makeSyscallInfo("sched_getaffinity", Hex, Hex, Hex),
	205: makeSyscallInfo("set_thread_area", Hex),
	206: makeSyscallInfo("io_setup", Hex, Hex),
	207: makeSyscallInfo("io_destroy", Hex),
	208: makeSyscallInfo("io_getevents", Hex, Hex, Hex, Hex, Timespec),
	209: makeSyscallInfo("io_submit", Hex, Hex, Hex),
	210: makeSyscallInfo("io_cancel", Hex, Hex, Hex),
	211: makeSyscallInfo("get_thread_area", Hex),
	212: makeSyscallInfo("lookup_dcookie", Hex, Hex, Hex),
	213: makeSyscallInfo("epoll_create", Hex),
	// 214: epoll_ctl_old (not implemented in the Linux kernel)
	// 215: epoll_wait_old (not implemented in the Linux kernel)
	216: makeSyscallInfo("remap_file_pages", Hex, Hex, Hex, Hex, Hex),
	217: makeSyscallInfo("getdents64", FD, Hex, Hex),
	218: makeSyscallInfo("set_tid_address", Hex),
	219: makeSyscallInfo("restart_syscall"),
	220: makeSyscallInfo("semtimedop", Hex, Hex, Hex, Hex),
	221: makeSyscallInfo("fadvise64", FD, Hex, Hex, Hex),
	222: makeSyscallInfo("timer_create", Hex, Hex, Hex),
	223: makeSyscallInfo("timer_settime", Hex, Hex, ItimerSpec, PostItimerSpec),
	224: makeSyscallInfo("timer_gettime", Hex, PostItimerSpec),
	225: makeSyscallInfo("timer_getoverrun", Hex),
	226: makeSyscallInfo("timer_delete", Hex),
	227: makeSyscallInfo("clock_settime", Hex, Timespec),
	228: makeSyscallInfo("clock_gettime", Hex, PostTimespec),
	229: makeSyscallInfo("clock_getres", Hex, PostTimespec),
	230: makeSyscallInfo("clock_nanosleep", Hex, Hex, Timespec, PostTimespec),
	231: makeSyscallInfo("exit_group", Hex),
	232: makeSyscallInfo("epoll_wait", Hex, Hex, Hex, Hex),
	233: makeSyscallInfo("epoll_ctl", Hex, Hex, FD, Hex),
	234: makeSyscallInfo("tgkill", Hex, Hex, Signal),
	235: makeSyscallInfo("utimes", Path, Timeval),
	// 236: vserver (not implemented in the Linux kernel)
	237: makeSyscallInfo("mbind", Hex, Hex, Hex, Hex, Hex, Hex),
	238: makeSyscallInfo("set_mempolicy", Hex, Hex, Hex),
	239: makeSyscallInfo("get_mempolicy", Hex, Hex, Hex, Hex, Hex),
	240: makeSyscallInfo("mq_open", Hex, Hex, Hex, Hex),
	241: makeSyscallInfo("mq_unlink", Hex),
	242: makeSyscallInfo("mq_timedsend", Hex, Hex, Hex, Hex, Hex),
	243: makeSyscallInfo("mq_timedreceive", Hex, Hex, Hex, Hex, Hex),
	244: makeSyscallInfo("mq_notify", Hex, Hex),
	245: makeSyscallInfo("mq_getsetattr", Hex, Hex, Hex),
	246: makeSyscallInfo("kexec_load", Hex, Hex, Hex, Hex),
	247: makeSyscallInfo("waitid", Hex, Hex, Hex, Hex, Rusage),
	248: makeSyscallInfo("add_key", Hex, Hex, Hex, Hex, Hex),
	249: makeSyscallInfo("request_key", Hex, Hex, Hex, Hex),
	250: makeSyscallInfo("keyctl", Hex, Hex, Hex, Hex, Hex),
	251: makeSyscallInfo("ioprio_set", Hex, Hex, Hex),
	252: makeSyscallInfo("ioprio_get", Hex, Hex),
	253: makeSyscallInfo("inotify_init"),
	254: makeSyscallInfo("inotify_add_watch", Hex, Path, Hex),
	255: makeSyscallInfo("inotify_rm_watch", Hex, Hex),
	256: makeSyscallInfo("migrate_pages", Hex, Hex, Hex, Hex),
	257: makeSyscallInfo("openat", FD, Path, OpenFlags, Mode),
	258: makeSyscallInfo("mkdirat", FD, Path, Hex),
	259: makeSyscallInfo("mknodat", FD, Path, Mode, Hex),
	260: makeSyscallInfo("fchownat", FD, Path, Hex, Hex, Hex),
	261: makeSyscallInfo("futimesat", FD, Path, Hex),
	262: makeSyscallInfo("newfstatat", FD, Path, Stat, Hex),
	263: makeSyscallInfo("unlinkat", FD, Path, Hex),
	264: makeSyscallInfo("renameat", FD, Path, Hex, Path),
	265: makeSyscallInfo("linkat", FD, Path, Hex, Path, Hex),
	266: makeSyscallInfo("symlinkat", Path, Hex, Path),
	267: makeSyscallInfo("readlinkat", FD, Path, ReadBuffer, Hex),
	268: makeSyscallInfo("fchmodat", FD, Path, Mode),
	269: makeSyscallInfo("faccessat", FD, Path, Oct, Hex),
	270: makeSyscallInfo("pselect6", Hex, SelectFDSet, SelectFDSet, SelectFDSet, Timespec, SigSet),
	271: makeSyscallInfo("ppoll", PollFDs, Hex, Timespec, SigSet, Hex),
	272: makeSyscallInfo("unshare", CloneFlags),
	273: makeSyscallInfo("set_robust_list", Hex, Hex),
	274: makeSyscallInfo("get_robust_list", Hex, Hex, Hex),
	275: makeSyscallInfo("splice", FD, Hex, FD, Hex, Hex, Hex),
	276: makeSyscallInfo("tee", FD, FD, Hex, Hex),
	277: makeSyscallInfo("sync_file_range", FD, Hex, Hex, Hex),
	278: makeSyscallInfo("vmsplice", FD, Hex, Hex, Hex),
	279: makeSyscallInfo("move_pages", Hex, Hex, Hex, Hex, Hex, Hex),
	280: makeSyscallInfo("utimensat", FD, Path, UTimeTimespec, Hex),
	281: makeSyscallInfo("epoll_pwait", Hex, Hex, Hex, Hex, SigSet, Hex),
	282: makeSyscallInfo("signalfd", Hex, Hex, Hex),
	283: makeSyscallInfo("timerfd_create", Hex, Hex),
	284: makeSyscallInfo("eventfd", Hex),
	285: makeSyscallInfo("fallocate", FD, Hex, Hex, Hex),
	286: makeSyscallInfo("timerfd_settime", FD, Hex, ItimerSpec, PostItimerSpec),
	287: makeSyscallInfo("timerfd_gettime", FD, PostItimerSpec),
	288: makeSyscallInfo("accept4", FD, PostSockAddr, SockLen, SockFlags),
	289: makeSyscallInfo("signalfd4", Hex, Hex, Hex, Hex),
	290: makeSyscallInfo("eventfd2", Hex, Hex),
	291: makeSyscallInfo("epoll_create1", Hex),
	292: makeSyscallInfo("dup3", FD, FD, Hex),
	293: makeSyscallInfo("pipe2", PipeFDs, Hex),
	294: makeSyscallInfo("inotify_init1", Hex),
	295: makeSyscallInfo("preadv", FD, ReadIOVec, Hex, Hex),
	296: makeSyscallInfo("pwritev", FD, WriteIOVec, Hex, Hex),
	297: makeSyscallInfo("rt_tgsigqueueinfo", Hex, Hex, Signal, Hex),
	298: makeSyscallInfo("perf_event_open", Hex, Hex, Hex, Hex, Hex),
	299: makeSyscallInfo("recvmmsg", FD, Hex, Hex, Hex, Hex),
	300: makeSyscallInfo("fanotify_init", Hex, Hex),
	301: makeSyscallInfo("fanotify_mark", Hex, Hex, Hex, Hex, Hex),
	302: makeSyscallInfo("prlimit64", Hex, Hex, Hex, Hex),
	303: makeSyscallInfo("name_to_handle_at", FD, Hex, Hex, Hex, Hex),
	304: makeSyscallInfo("open_by_handle_at", FD, Hex, Hex),
	305: makeSyscallInfo("clock_adjtime", Hex, Hex),
	306: makeSyscallInfo("syncfs", FD),
	307: makeSyscallInfo("sendmmsg", FD, Hex, Hex, Hex),
	308: makeSyscallInfo("setns", FD, Hex),
	309: makeSyscallInfo("getcpu", Hex, Hex, Hex),
	310: makeSyscallInfo("process_vm_readv", Hex, ReadIOVec, Hex, IOVec, Hex, Hex),
	311: makeSyscallInfo("process_vm_writev", Hex, IOVec, Hex, WriteIOVec, Hex, Hex),
	312: makeSyscallInfo("kcmp", Hex, Hex, Hex, Hex, Hex),
	313: makeSyscallInfo("finit_module", Hex, Hex, Hex),
	314: makeSyscallInfo("sched_setattr", Hex, Hex, Hex),
	315: makeSyscallInfo("sched_getattr", Hex, Hex, Hex),
	316: makeSyscallInfo("renameat2", FD, Path, Hex, Path, Hex),
	317: makeSyscallInfo("seccomp", Hex, Hex, Hex),
	318: makeSyscallInfo("getrandom", Hex, Hex, Hex),
	319: makeSyscallInfo("memfd_create", Path, Hex), // Not quite a path, but close.
	320: makeSyscallInfo("kexec_file_load", FD, FD, Hex, Hex, Hex),
	321: makeSyscallInfo("bpf", Hex, Hex, Hex),
	322: makeSyscallInfo("execveat", FD, Path, ExecveStringVector, ExecveStringVector, Hex),
	323: makeSyscallInfo("userfaultfd", Hex),
	324: makeSyscallInfo("membarrier", Hex, Hex),
	325: makeSyscallInfo("mlock2", Hex, Hex, Hex),
	326: makeSyscallInfo("copy_file_range", FD, Hex, FD, Hex, Hex, Hex),
	327: makeSyscallInfo("preadv2", FD, ReadIOVec, Hex, Hex, Hex),
	328: makeSyscallInfo("pwritev2", FD, WriteIOVec, Hex, Hex, Hex),
	329: makeSyscallInfo("pkey_mprotect", Hex, Hex, Hex, Hex),
	330: makeSyscallInfo("pkey_alloc", Hex, Hex),
	331: makeSyscallInfo("pkey_free", Hex),
	332: makeSyscallInfo("statx", FD, Path, Hex, Hex, Hex),
	333: makeSyscallInfo("io_pgetevents", Hex, Hex, Hex, Hex, Timespec, SigSet),
	334: makeSyscallInfo("rseq", Hex, Hex, Hex, Hex),
	424: makeSyscallInfo("pidfd_send_signal", FD, Signal, Hex, Hex),
	425: makeSyscallInfo("io_uring_setup", Hex, Hex),
	426: makeSyscallInfo("io_uring_enter", FD, Hex, Hex, Hex, SigSet, Hex),
	427: makeSyscallInfo("io_uring_register", FD, Hex, Hex, Hex),
	428: makeSyscallInfo("open_tree", FD, Path, Hex),
	429: makeSyscallInfo("move_mount", FD, Path, FD, Path, Hex),
	430: makeSyscallInfo("fsopen", Path, Hex), // Not quite a path, but close.
	431: makeSyscallInfo("fsconfig", FD, Hex, Hex, Hex, Hex),
	432: makeSyscallInfo("fsmount", FD, Hex, Hex),
	433: makeSyscallInfo("fspick", FD, Path, Hex),
	434: makeSyscallInfo("pidfd_open", Hex, Hex),
	435: makeSyscallInfo("clone3", Hex, Hex),
}

func init() {
	syscallTables = append(syscallTables,
		syscallTable{
			os:       abi.Linux,
			arch:     arch.AMD64,
			syscalls: linuxAMD64,
		},
	)
}
