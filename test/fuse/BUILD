load("//test/runner:defs.bzl", "syscall_test")

package(licenses = ["notice"])

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:stat_test",
    vfs2 = "True",
)


syscall_test(
    size = "large",
    add_overlay = True,
    debug = False,
    setup_command = "'./server-bin mountpoint'",
    test = "//test/fuse/benchmark:stat_benchmark",
    use_image = "basic/fuse",
)

syscall_test(
    size = "large",
    add_overlay = True,
    debug = False,
    setup_command = "'./server-bin mountpoint'",
    test = "//test/fuse/benchmark:open_benchmark",
    use_image = "basic/fuse",
)

syscall_test(
    size = "large",
    add_overlay = True,
    debug = False,
    setup_command = "'./server-bin mountpoint'",
    test = "//test/fuse/benchmark:read_benchmark",
    use_image = "basic/fuse",
)

syscall_test(
    size = "large",
    add_overlay = True,
    debug = False,
    setup_command = "'./server-bin mountpoint'",
    test = "//test/fuse/benchmark:symlink_benchmark",
    use_image = "basic/fuse",
)

syscall_test(
    size = "large",
    add_overlay = True,
    debug = False,
    setup_command = "'./server-bin mountpoint'",
    test = "//test/fuse/benchmark:mkdir_benchmark",
    use_image = "basic/fuse",
)
