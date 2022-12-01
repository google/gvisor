load("//tools:defs.bzl", "go_library", "go_test", "proto_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")

package(licenses = ["notice"])

declare_mutex(
    name = "cpu_clock_mutex",
    out = "cpu_clock_mutex.go",
    package = "kernel",
    prefix = "cpuClock",
)

declare_mutex(
    name = "user_counters_mutex",
    out = "user_counters_mutex.go",
    package = "kernel",
    prefix = "userCounters",
)

declare_rwmutex(
    name = "taskset_mutex",
    out = "taskset_mutex.go",
    package = "kernel",
    prefix = "taskSet",
)

declare_mutex(
    name = "task_mutex",
    out = "task_mutex.go",
    nested_lock_names = ["child"],
    package = "kernel",
    prefix = "task",
)

declare_mutex(
    name = "cgroup_mutex",
    out = "cgroup_mutex.go",
    package = "kernel",
    prefix = "cgroup",
)

declare_mutex(
    name = "fd_table_mutex",
    out = "fd_table_mutex.go",
    package = "kernel",
    prefix = "fdTable",
)

declare_mutex(
    name = "running_tasks_mutex",
    out = "running_tasks_mutex.go",
    package = "kernel",
    prefix = "runningTasks",
)

declare_mutex(
    name = "signal_handlers_mutex",
    out = "signal_handlers_mutex.go",
    nested_lock_names = ["tg"],
    package = "kernel",
    prefix = "signalHandlers",
)

declare_mutex(
    name = "thread_group_timer_mutex",
    out = "thread_group_timer_mutex.go",
    package = "kernel",
    prefix = "threadGroupTimer",
)

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
    out = "seqatomic_taskgoroutineschedinfo_unsafe.go",
    package = "kernel",
    suffix = "TaskGoroutineSchedInfo",
    template = "//pkg/sync/seqatomic:generic_seqatomic",
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
    name = "fd_table_refs",
    out = "fd_table_refs.go",
    package = "kernel",
    prefix = "FDTable",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "FDTable",
    },
)

go_template_instance(
    name = "fs_context_refs",
    out = "fs_context_refs.go",
    package = "kernel",
    prefix = "FSContext",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "FSContext",
    },
)

go_template_instance(
    name = "ipc_namespace_refs",
    out = "ipc_namespace_refs.go",
    package = "kernel",
    prefix = "IPCNamespace",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "IPCNamespace",
    },
)

go_template_instance(
    name = "process_group_refs",
    out = "process_group_refs.go",
    package = "kernel",
    prefix = "ProcessGroup",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "ProcessGroup",
    },
)

go_template_instance(
    name = "session_refs",
    out = "session_refs.go",
    package = "kernel",
    prefix = "Session",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "Session",
    },
)

proto_library(
    name = "uncaught_signal",
    srcs = ["uncaught_signal.proto"],
    visibility = ["//visibility:public"],
    deps = ["//pkg/sentry/arch:registers_proto"],
)

go_library(
    name = "kernel",
    srcs = [
        "abstract_socket_namespace.go",
        "aio.go",
        "cgroup.go",
        "cgroup_mutex.go",
        "context.go",
        "cpu_clock_mutex.go",
        "fd_table.go",
        "fd_table_mutex.go",
        "fd_table_refs.go",
        "fd_table_unsafe.go",
        "fs_context.go",
        "fs_context_refs.go",
        "ipc_namespace.go",
        "ipc_namespace_refs.go",
        "kcov.go",
        "kcov_unsafe.go",
        "kernel.go",
        "kernel_opts.go",
        "kernel_state.go",
        "pending_signals.go",
        "pending_signals_list.go",
        "pending_signals_state.go",
        "posixtimer.go",
        "process_group_list.go",
        "process_group_refs.go",
        "ptrace.go",
        "ptrace_amd64.go",
        "ptrace_arm64.go",
        "rseq.go",
        "running_tasks_mutex.go",
        "seccheck.go",
        "seccomp.go",
        "seqatomic_taskgoroutineschedinfo_unsafe.go",
        "session_list.go",
        "session_refs.go",
        "sessions.go",
        "signal.go",
        "signal_handlers.go",
        "signal_handlers_mutex.go",
        "syscalls.go",
        "syscalls_state.go",
        "syslog.go",
        "task.go",
        "task_acct.go",
        "task_block.go",
        "task_cgroup.go",
        "task_clone.go",
        "task_context.go",
        "task_exec.go",
        "task_exit.go",
        "task_futex.go",
        "task_identity.go",
        "task_image.go",
        "task_list.go",
        "task_log.go",
        "task_mutex.go",
        "task_net.go",
        "task_run.go",
        "task_sched.go",
        "task_signals.go",
        "task_start.go",
        "task_stop.go",
        "task_syscall.go",
        "task_usermem.go",
        "task_work.go",
        "taskset_mutex.go",
        "thread_group.go",
        "thread_group_timer_mutex.go",
        "threads.go",
        "threads_impl.go",
        "timekeeper.go",
        "timekeeper_state.go",
        "tty.go",
        "user_counters_mutex.go",
        "uts_namespace.go",
        "vdso.go",
        "version.go",
    ],
    imports = [
        "gvisor.dev/gvisor/pkg/bpf",
        "gvisor.dev/gvisor/pkg/sentry/device",
        "gvisor.dev/gvisor/pkg/tcpip",
    ],
    marshal = True,
    visibility = ["//:sandbox"],
    deps = [
        ":uncaught_signal_go_proto",
        "//pkg/abi",
        "//pkg/abi/linux",
        "//pkg/abi/linux/errno",
        "//pkg/atomicbitops",
        "//pkg/bitmap",
        "//pkg/bits",
        "//pkg/bpf",
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/coverage",
        "//pkg/cpuid",
        "//pkg/errors",
        "//pkg/errors/linuxerr",
        "//pkg/eventchannel",
        "//pkg/fspath",
        "//pkg/goid",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/metric",
        "//pkg/refs",
        "//pkg/safemem",
        "//pkg/secio",
        "//pkg/sentry/arch",
        "//pkg/sentry/device",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/fsimpl/lock",
        "//pkg/sentry/fsimpl/mqfs",
        "//pkg/sentry/fsimpl/pipefs",
        "//pkg/sentry/fsimpl/sockfs",
        "//pkg/sentry/fsimpl/timerfd",
        "//pkg/sentry/fsimpl/tmpfs",
        "//pkg/sentry/hostcpu",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/futex",
        "//pkg/sentry/kernel/ipc",
        "//pkg/sentry/kernel/mq",
        "//pkg/sentry/kernel/msgqueue",
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
        "//pkg/sentry/seccheck",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sentry/socket/netlink/port",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/time",
        "//pkg/sentry/unimpl",
        "//pkg/sentry/unimpl:unimplemented_syscall_go_proto",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/state",
        "//pkg/state/statefile",
        "//pkg/state/wire",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "kernel_test",
    size = "small",
    srcs = [
        "fd_table_test.go",
        "table_test.go",
        "task_test.go",
        "timekeeper_test.go",
    ],
    library = ":kernel",
    deps = [
        "//pkg/abi",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/sentry/arch",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/kernel/sched",
        "//pkg/sentry/limits",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/time",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/sync",
    ],
)
