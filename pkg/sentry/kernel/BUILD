load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_template_instance(
    name = "pending_signals_list",
    out = "pending_signals_list.go",
    package = "kernel",
    prefix = "pendingSignal",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*pendingSignal",
        "Linker": "*pendingSignal",
    },
)

go_template_instance(
    name = "process_group_list",
    out = "process_group_list.go",
    package = "kernel",
    prefix = "processGroup",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*ProcessGroup",
        "Linker": "*ProcessGroup",
    },
)

go_template_instance(
    name = "seqatomic_taskgoroutineschedinfo",
    out = "seqatomic_taskgoroutineschedinfo.go",
    package = "kernel",
    suffix = "TaskGoroutineSchedInfo",
    template = "//third_party/gvsync:generic_seqatomic",
    types = {
        "Value": "TaskGoroutineSchedInfo",
    },
)

go_template_instance(
    name = "session_list",
    out = "session_list.go",
    package = "kernel",
    prefix = "session",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*Session",
        "Linker": "*Session",
    },
)

go_template_instance(
    name = "task_list",
    out = "task_list.go",
    package = "kernel",
    prefix = "task",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*Task",
        "Linker": "*Task",
    },
)

go_template_instance(
    name = "socket_list",
    out = "socket_list.go",
    package = "kernel",
    prefix = "socket",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*SocketEntry",
        "Linker": "*SocketEntry",
    },
)

proto_library(
    name = "uncaught_signal_proto",
    srcs = ["uncaught_signal.proto"],
    visibility = ["//visibility:public"],
    deps = ["//pkg/sentry/arch:registers_proto"],
)

go_proto_library(
    name = "uncaught_signal_go_proto",
    importpath = "gvisor.dev/gvisor/pkg/sentry/kernel/uncaught_signal_go_proto",
    proto = ":uncaught_signal_proto",
    visibility = ["//visibility:public"],
    deps = ["//pkg/sentry/arch:registers_go_proto"],
)

go_library(
    name = "kernel",
    srcs = [
        "abstract_socket_namespace.go",
        "context.go",
        "fd_map.go",
        "fs_context.go",
        "ipc_namespace.go",
        "kernel.go",
        "kernel_state.go",
        "pending_signals.go",
        "pending_signals_list.go",
        "pending_signals_state.go",
        "posixtimer.go",
        "process_group_list.go",
        "ptrace.go",
        "ptrace_amd64.go",
        "ptrace_arm64.go",
        "rseq.go",
        "seccomp.go",
        "seqatomic_taskgoroutineschedinfo.go",
        "session_list.go",
        "sessions.go",
        "signal.go",
        "signal_handlers.go",
        "socket_list.go",
        "syscalls.go",
        "syscalls_state.go",
        "syslog.go",
        "task.go",
        "task_acct.go",
        "task_block.go",
        "task_clone.go",
        "task_context.go",
        "task_exec.go",
        "task_exit.go",
        "task_futex.go",
        "task_identity.go",
        "task_list.go",
        "task_log.go",
        "task_net.go",
        "task_run.go",
        "task_sched.go",
        "task_signals.go",
        "task_start.go",
        "task_stop.go",
        "task_syscall.go",
        "task_usermem.go",
        "thread_group.go",
        "threads.go",
        "timekeeper.go",
        "timekeeper_state.go",
        "uts_namespace.go",
        "vdso.go",
        "version.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/kernel",
    imports = [
        "gvisor.dev/gvisor/pkg/bpf",
        "gvisor.dev/gvisor/pkg/sentry/device",
        "gvisor.dev/gvisor/pkg/tcpip",
    ],
    visibility = ["//:sandbox"],
    deps = [
        ":uncaught_signal_go_proto",
        "//pkg/abi",
        "//pkg/abi/linux",
        "//pkg/amutex",
        "//pkg/binary",
        "//pkg/bits",
        "//pkg/bpf",
        "//pkg/cpuid",
        "//pkg/eventchannel",
        "//pkg/log",
        "//pkg/metric",
        "//pkg/refs",
        "//pkg/secio",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/fs/timerfd",
        "//pkg/sentry/hostcpu",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/epoll",
        "//pkg/sentry/kernel/futex",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/kernel/sched",
        "//pkg/sentry/kernel/semaphore",
        "//pkg/sentry/kernel/shm",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/limits",
        "//pkg/sentry/loader",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/safemem",
        "//pkg/sentry/socket/netlink/port",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/time",
        "//pkg/sentry/unimpl",
        "//pkg/sentry/unimpl:unimplemented_syscall_go_proto",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/state/statefile",
        "//pkg/syserr",
        "//pkg/syserror",
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
        "//pkg/waiter",
        "//third_party/gvsync",
    ],
)

go_test(
    name = "kernel_test",
    size = "small",
    srcs = [
        "fd_map_test.go",
        "table_test.go",
        "task_test.go",
        "timekeeper_test.go",
    ],
    embed = [":kernel"],
    deps = [
        "//pkg/abi",
        "//pkg/sentry/arch",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs/filetest",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/kernel/sched",
        "//pkg/sentry/limits",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/time",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
    ],
)
