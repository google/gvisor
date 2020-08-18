load("//test/runner:defs.bzl", "syscall_test")

package(licenses = ["notice"])

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:stat_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:open_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:release_test",
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
