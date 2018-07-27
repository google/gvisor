# Package linux contains the constants and types needed to inferface with a
# Linux kernel. It should be used instead of syscall or golang.org/x/sys/unix
# when the host OS may not be Linux.

package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify")

go_stateify(
    name = "linux_state",
    srcs = [
        "binder.go",
        "bpf.go",
        "time.go",
        "tty.go",
    ],
    out = "linux_state.go",
    package = "linux",
)

go_library(
    name = "linux",
    srcs = [
        "aio.go",
        "ashmem.go",
        "binder.go",
        "bpf.go",
        "capability.go",
        "dev.go",
        "elf.go",
        "errors.go",
        "eventfd.go",
        "exec.go",
        "fcntl.go",
        "file.go",
        "fs.go",
        "futex.go",
        "inotify.go",
        "ioctl.go",
        "ip.go",
        "ipc.go",
        "limits.go",
        "linux.go",
        "linux_state.go",
        "mm.go",
        "netdevice.go",
        "netlink.go",
        "netlink_route.go",
        "poll.go",
        "prctl.go",
        "ptrace.go",
        "rusage.go",
        "sched.go",
        "seccomp.go",
        "sem.go",
        "shm.go",
        "signal.go",
        "socket.go",
        "time.go",
        "tty.go",
        "uio.go",
        "utsname.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/abi/linux",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi",
        "//pkg/binary",
        "//pkg/bits",
        "//pkg/state",
    ],
)
