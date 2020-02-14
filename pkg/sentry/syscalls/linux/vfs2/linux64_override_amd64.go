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

package vfs2

import (
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/syscalls"
)

// Override syscall table to add syscalls implementations from this package.
func Override(table map[uintptr]kernel.Syscall) {
	table[0] = syscalls.Supported("read", Read)

	// Remove syscalls that haven't been converted yet. It's better to get ENOSYS
	// rather than a SIGSEGV deep in the stack.
	delete(table, 1)   // write
	delete(table, 2)   // open
	delete(table, 3)   // close
	delete(table, 4)   // stat
	delete(table, 5)   // fstat
	delete(table, 6)   // lstat
	delete(table, 7)   // poll
	delete(table, 8)   // lseek
	delete(table, 9)   // mmap
	delete(table, 16)  // ioctl
	delete(table, 17)  // pread64
	delete(table, 18)  // pwrite64
	delete(table, 19)  // readv
	delete(table, 20)  // writev
	delete(table, 21)  // access
	delete(table, 22)  // pipe
	delete(table, 32)  // dup
	delete(table, 33)  // dup2
	delete(table, 40)  // sendfile
	delete(table, 59)  // execve
	delete(table, 72)  // fcntl
	delete(table, 73)  // flock
	delete(table, 74)  // fsync
	delete(table, 75)  // fdatasync
	delete(table, 76)  // truncate
	delete(table, 77)  // ftruncate
	delete(table, 78)  // getdents
	delete(table, 79)  // getcwd
	delete(table, 80)  // chdir
	delete(table, 81)  // fchdir
	delete(table, 82)  // rename
	delete(table, 83)  // mkdir
	delete(table, 84)  // rmdir
	delete(table, 85)  // creat
	delete(table, 86)  // link
	delete(table, 87)  // unlink
	delete(table, 88)  // symlink
	delete(table, 89)  // readlink
	delete(table, 90)  // chmod
	delete(table, 91)  // fchmod
	delete(table, 92)  // chown
	delete(table, 93)  // fchown
	delete(table, 94)  // lchown
	delete(table, 133) // mknod
	delete(table, 137) // statfs
	delete(table, 138) // fstatfs
	delete(table, 161) // chroot
	delete(table, 162) // sync
	delete(table, 165) // mount
	delete(table, 166) // umount2
	delete(table, 172) // iopl
	delete(table, 173) // ioperm
	delete(table, 187) // readahead
	delete(table, 188) // setxattr
	delete(table, 189) // lsetxattr
	delete(table, 190) // fsetxattr
	delete(table, 191) // getxattr
	delete(table, 192) // lgetxattr
	delete(table, 193) // fgetxattr
	delete(table, 206) // io_setup
	delete(table, 207) // io_destroy
	delete(table, 208) // io_getevents
	delete(table, 209) // io_submit
	delete(table, 210) // io_cancel
	delete(table, 213) // epoll_create
	delete(table, 214) // epoll_ctl_old
	delete(table, 215) // epoll_wait_old
	delete(table, 216) // remap_file_pages
	delete(table, 217) // getdents64
	delete(table, 232) // epoll_wait
	delete(table, 233) // epoll_ctl
	delete(table, 253) // inotify_init
	delete(table, 254) // inotify_add_watch
	delete(table, 255) // inotify_rm_watch
	delete(table, 257) // openat
	delete(table, 258) // mkdirat
	delete(table, 259) // mknodat
	delete(table, 260) // fchownat
	delete(table, 261) // futimesat
	delete(table, 262) // fstatat
	delete(table, 263) // unlinkat
	delete(table, 264) // renameat
	delete(table, 265) // linkat
	delete(table, 266) // symlinkat
	delete(table, 267) // readlinkat
	delete(table, 268) // fchmodat
	delete(table, 269) // faccessat
	delete(table, 270) // pselect
	delete(table, 271) // ppoll
	delete(table, 285) // fallocate
	delete(table, 291) // epoll_create1
	delete(table, 292) // dup3
	delete(table, 293) // pipe2
	delete(table, 294) // inotify_init1
	delete(table, 295) // preadv
	delete(table, 296) // pwritev
	delete(table, 306) // syncfs
	delete(table, 316) // renameat2
	delete(table, 319) // memfd_create
	delete(table, 322) // execveat
	delete(table, 327) // preadv2
	delete(table, 328) // pwritev2
	delete(table, 332) // statx
}
