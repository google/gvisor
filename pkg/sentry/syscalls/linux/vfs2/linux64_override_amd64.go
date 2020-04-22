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

// +build amd64

package vfs2

import (
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/syscalls"
)

// Override syscall table to add syscalls implementations from this package.
func Override(table map[uintptr]kernel.Syscall) {
	table[0] = syscalls.Supported("read", Read)
	table[1] = syscalls.Supported("write", Write)
	table[2] = syscalls.Supported("open", Open)
	table[3] = syscalls.Supported("close", Close)
	table[4] = syscalls.Supported("stat", Stat)
	table[5] = syscalls.Supported("fstat", Fstat)
	table[6] = syscalls.Supported("lstat", Lstat)
	table[7] = syscalls.Supported("poll", Poll)
	table[8] = syscalls.Supported("lseek", Lseek)
	table[9] = syscalls.Supported("mmap", Mmap)
	table[16] = syscalls.Supported("ioctl", Ioctl)
	table[17] = syscalls.Supported("pread64", Pread64)
	table[18] = syscalls.Supported("pwrite64", Pwrite64)
	table[19] = syscalls.Supported("readv", Readv)
	table[20] = syscalls.Supported("writev", Writev)
	table[21] = syscalls.Supported("access", Access)
	table[22] = syscalls.Supported("pipe", Pipe)
	table[23] = syscalls.Supported("select", Select)
	table[32] = syscalls.Supported("dup", Dup)
	table[33] = syscalls.Supported("dup2", Dup2)
	delete(table, 40) // sendfile
	// TODO(gvisor.dev/issue/1485): Port all socket variants to VFS2.
	table[41] = syscalls.PartiallySupported("socket", Socket, "In process of porting socket syscalls to VFS2.", nil)
	table[42] = syscalls.PartiallySupported("connect", Connect, "In process of porting socket syscalls to VFS2.", nil)
	table[43] = syscalls.PartiallySupported("accept", Accept, "In process of porting socket syscalls to VFS2.", nil)
	table[44] = syscalls.PartiallySupported("sendto", SendTo, "In process of porting socket syscalls to VFS2.", nil)
	table[45] = syscalls.PartiallySupported("recvfrom", RecvFrom, "In process of porting socket syscalls to VFS2.", nil)
	table[46] = syscalls.PartiallySupported("sendmsg", SendMsg, "In process of porting socket syscalls to VFS2.", nil)
	table[47] = syscalls.PartiallySupported("recvmsg", RecvMsg, "In process of porting socket syscalls to VFS2.", nil)
	table[48] = syscalls.PartiallySupported("shutdown", Shutdown, "In process of porting socket syscalls to VFS2.", nil)
	table[49] = syscalls.PartiallySupported("bind", Bind, "In process of porting socket syscalls to VFS2.", nil)
	table[50] = syscalls.PartiallySupported("listen", Listen, "In process of porting socket syscalls to VFS2.", nil)
	table[51] = syscalls.PartiallySupported("getsockname", GetSockName, "In process of porting socket syscalls to VFS2.", nil)
	table[52] = syscalls.PartiallySupported("getpeername", GetPeerName, "In process of porting socket syscalls to VFS2.", nil)
	table[53] = syscalls.PartiallySupported("socketpair", SocketPair, "In process of porting socket syscalls to VFS2.", nil)
	table[54] = syscalls.PartiallySupported("setsockopt", SetSockOpt, "In process of porting socket syscalls to VFS2.", nil)
	table[55] = syscalls.PartiallySupported("getsockopt", GetSockOpt, "In process of porting socket syscalls to VFS2.", nil)
	table[59] = syscalls.Supported("execve", Execve)
	table[72] = syscalls.Supported("fcntl", Fcntl)
	delete(table, 73) // flock
	table[74] = syscalls.Supported("fsync", Fsync)
	table[75] = syscalls.Supported("fdatasync", Fdatasync)
	table[76] = syscalls.Supported("truncate", Truncate)
	table[77] = syscalls.Supported("ftruncate", Ftruncate)
	table[78] = syscalls.Supported("getdents", Getdents)
	table[79] = syscalls.Supported("getcwd", Getcwd)
	table[80] = syscalls.Supported("chdir", Chdir)
	table[81] = syscalls.Supported("fchdir", Fchdir)
	table[82] = syscalls.Supported("rename", Rename)
	table[83] = syscalls.Supported("mkdir", Mkdir)
	table[84] = syscalls.Supported("rmdir", Rmdir)
	table[85] = syscalls.Supported("creat", Creat)
	table[86] = syscalls.Supported("link", Link)
	table[87] = syscalls.Supported("unlink", Unlink)
	table[88] = syscalls.Supported("symlink", Symlink)
	table[89] = syscalls.Supported("readlink", Readlink)
	table[90] = syscalls.Supported("chmod", Chmod)
	table[91] = syscalls.Supported("fchmod", Fchmod)
	table[92] = syscalls.Supported("chown", Chown)
	table[93] = syscalls.Supported("fchown", Fchown)
	table[94] = syscalls.Supported("lchown", Lchown)
	table[132] = syscalls.Supported("utime", Utime)
	table[133] = syscalls.Supported("mknod", Mknod)
	table[137] = syscalls.Supported("statfs", Statfs)
	table[138] = syscalls.Supported("fstatfs", Fstatfs)
	table[161] = syscalls.Supported("chroot", Chroot)
	table[162] = syscalls.Supported("sync", Sync)
	delete(table, 165) // mount
	delete(table, 166) // umount2
	delete(table, 187) // readahead
	table[188] = syscalls.Supported("setxattr", Setxattr)
	table[189] = syscalls.Supported("lsetxattr", Lsetxattr)
	table[190] = syscalls.Supported("fsetxattr", Fsetxattr)
	table[191] = syscalls.Supported("getxattr", Getxattr)
	table[192] = syscalls.Supported("lgetxattr", Lgetxattr)
	table[193] = syscalls.Supported("fgetxattr", Fgetxattr)
	table[194] = syscalls.Supported("listxattr", Listxattr)
	table[195] = syscalls.Supported("llistxattr", Llistxattr)
	table[196] = syscalls.Supported("flistxattr", Flistxattr)
	table[197] = syscalls.Supported("removexattr", Removexattr)
	table[198] = syscalls.Supported("lremovexattr", Lremovexattr)
	table[199] = syscalls.Supported("fremovexattr", Fremovexattr)
	delete(table, 206) // io_setup
	delete(table, 207) // io_destroy
	delete(table, 208) // io_getevents
	delete(table, 209) // io_submit
	delete(table, 210) // io_cancel
	table[213] = syscalls.Supported("epoll_create", EpollCreate)
	table[217] = syscalls.Supported("getdents64", Getdents64)
	delete(table, 221) // fdavise64
	table[232] = syscalls.Supported("epoll_wait", EpollWait)
	table[233] = syscalls.Supported("epoll_ctl", EpollCtl)
	table[235] = syscalls.Supported("utimes", Utimes)
	delete(table, 253) // inotify_init
	delete(table, 254) // inotify_add_watch
	delete(table, 255) // inotify_rm_watch
	table[257] = syscalls.Supported("openat", Openat)
	table[258] = syscalls.Supported("mkdirat", Mkdirat)
	table[259] = syscalls.Supported("mknodat", Mknodat)
	table[260] = syscalls.Supported("fchownat", Fchownat)
	table[261] = syscalls.Supported("futimens", Futimens)
	table[262] = syscalls.Supported("newfstatat", Newfstatat)
	table[263] = syscalls.Supported("unlinkat", Unlinkat)
	table[264] = syscalls.Supported("renameat", Renameat)
	table[265] = syscalls.Supported("linkat", Linkat)
	table[266] = syscalls.Supported("symlinkat", Symlinkat)
	table[267] = syscalls.Supported("readlinkat", Readlinkat)
	table[268] = syscalls.Supported("fchmodat", Fchmodat)
	table[269] = syscalls.Supported("faccessat", Faccessat)
	table[270] = syscalls.Supported("pselect", Pselect)
	table[271] = syscalls.Supported("ppoll", Ppoll)
	delete(table, 275) // splice
	delete(table, 276) // tee
	table[277] = syscalls.Supported("sync_file_range", SyncFileRange)
	table[280] = syscalls.Supported("utimensat", Utimensat)
	table[281] = syscalls.Supported("epoll_pwait", EpollPwait)
	delete(table, 282) // signalfd
	table[283] = syscalls.Supported("timerfd_create", TimerfdCreate)
	delete(table, 284) // eventfd
	delete(table, 285) // fallocate
	table[286] = syscalls.Supported("timerfd_settime", TimerfdSettime)
	table[287] = syscalls.Supported("timerfd_gettime", TimerfdGettime)
	// TODO(gvisor.dev/issue/1485): Port all socket variants to VFS2.
	table[288] = syscalls.PartiallySupported("accept4", Accept4, "In process of porting socket syscalls to VFS2.", nil)
	delete(table, 289) // signalfd4
	delete(table, 290) // eventfd2
	table[291] = syscalls.Supported("epoll_create1", EpollCreate1)
	table[292] = syscalls.Supported("dup3", Dup3)
	table[293] = syscalls.Supported("pipe2", Pipe2)
	delete(table, 294) // inotify_init1
	table[295] = syscalls.Supported("preadv", Preadv)
	table[296] = syscalls.Supported("pwritev", Pwritev)
	// TODO(gvisor.dev/issue/1485): Port all socket variants to VFS2.
	table[299] = syscalls.PartiallySupported("recvmmsg", RecvMMsg, "In process of porting socket syscalls to VFS2.", nil)
	table[306] = syscalls.Supported("syncfs", Syncfs)
	// TODO(gvisor.dev/issue/1485): Port all socket variants to VFS2.
	table[307] = syscalls.PartiallySupported("sendmmsg", SendMMsg, "In process of porting socket syscalls to VFS2.", nil)
	table[316] = syscalls.Supported("renameat2", Renameat2)
	delete(table, 319) // memfd_create
	table[322] = syscalls.Supported("execveat", Execveat)
	table[327] = syscalls.Supported("preadv2", Preadv2)
	table[328] = syscalls.Supported("pwritev2", Pwritev2)
	table[332] = syscalls.Supported("statx", Statx)
}
