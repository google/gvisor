load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

go_template_instance(
    name = "fd_dir_inode_refs",
    out = "fd_dir_inode_refs.go",
    package = "proc",
    prefix = "fdDirInode",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "fdDirInode",
    },
)

go_template_instance(
    name = "fd_info_dir_inode_refs",
    out = "fd_info_dir_inode_refs.go",
    package = "proc",
    prefix = "fdInfoDirInode",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "fdInfoDirInode",
    },
)

go_template_instance(
    name = "subtasks_inode_refs",
    out = "subtasks_inode_refs.go",
    package = "proc",
    prefix = "subtasksInode",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "subtasksInode",
    },
)

go_template_instance(
    name = "task_inode_refs",
    out = "task_inode_refs.go",
    package = "proc",
    prefix = "taskInode",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "taskInode",
    },
)

go_template_instance(
    name = "tasks_inode_refs",
    out = "tasks_inode_refs.go",
    package = "proc",
    prefix = "tasksInode",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "tasksInode",
    },
)

go_library(
    name = "proc",
    srcs = [
        "fd_dir_inode_refs.go",
        "fd_info_dir_inode_refs.go",
        "filesystem.go",
        "subtasks.go",
        "subtasks_inode_refs.go",
        "task.go",
        "task_fds.go",
        "task_files.go",
        "task_inode_refs.go",
        "task_net.go",
        "tasks.go",
        "tasks_files.go",
        "tasks_inode_refs.go",
        "tasks_sys.go",
        "yama.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/safemem",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/fsbridge",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/limits",
        "//pkg/sentry/mm",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/unix",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/tcpip/header",
        "//pkg/tcpip/network/ipv4",
        "//pkg/usermem",
    ],
)

go_test(
    name = "proc_test",
    size = "small",
    srcs = [
        "tasks_sys_test.go",
        "tasks_test.go",
    ],
    library = ":proc",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fsimpl/testutil",
        "//pkg/sentry/fsimpl/tmpfs",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)
