load("//test/runner:defs.bzl", "syscall_test")

package(licenses = ["notice"])

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:stat_test",
    vfs2 = "True",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:mknod_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:symlink_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:readlink_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:mkdir_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:unlink_test",
)
