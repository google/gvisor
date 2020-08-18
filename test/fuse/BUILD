load("//test/runner:defs.bzl", "syscall_test")

package(licenses = ["notice"])

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:stat_test",
    vfs2 = "True",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:open_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:release_test",
)
