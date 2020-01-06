load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_stateify:defs.bzl", "go_library")

# Package linux contains the constants and types needed to interface with a
# Linux kernel. It should be used instead of syscall or golang.org/x/sys/unix
# when the host OS may not be Linux.

package(licenses = ["notice"])

go_library(
    name = "linux",
    srcs = [
        "aio.go",
        "audit.go",
        "bpf.go",
        "capability.go",
        "clone.go",
        "dev.go",
        "elf.go",
        "epoll.go",
        "errors.go",
        "eventfd.go",
        "exec.go",
        "fcntl.go",
        "file.go",
        "file_amd64.go",
        "file_arm64.go",
        "fs.go",
        "futex.go",
        "inotify.go",
        "ioctl.go",
        "ip.go",
        "ipc.go",
        "limits.go",
        "linux.go",
        "mm.go",
        "netdevice.go",
        "netfilter.go",
        "netlink.go",
        "netlink_route.go",
        "poll.go",
        "prctl.go",
        "ptrace.go",
        "rseq.go",
        "rusage.go",
        "sched.go",
        "seccomp.go",
        "sem.go",
        "shm.go",
        "signal.go",
        "signalfd.go",
        "socket.go",
        "splice.go",
        "tcp.go",
        "time.go",
        "timer.go",
        "tty.go",
        "uio.go",
        "utsname.go",
        "wait.go",
        "xattr.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/abi/linux",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi",
        "//pkg/binary",
        "//pkg/bits",
    ],
)

go_test(
    name = "linux_test",
    size = "small",
    srcs = ["netfilter_test.go"],
    embed = [":linux"],
    deps = [
        "//pkg/binary",
    ],
)
