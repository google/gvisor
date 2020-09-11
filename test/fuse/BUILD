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

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:mkdir_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:read_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:write_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:rmdir_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:readdir_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:create_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:unlink_test",
)

syscall_test(
    fuse = "True",
    test = "//test/fuse/linux:setstat_test",
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
