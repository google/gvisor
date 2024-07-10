load("//test/runner:defs.bzl", "syscall_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

syscall_test(
    size = "small",
    container = True,
    overlay = True,
    save = False,
    test = "//test/rtnetlink/linux:veth_test",
    use_tmpfs = True,
)

syscall_test(
    size = "small",
    container = True,
    overlay = True,
    save = False,
    test = "//test/rtnetlink/linux:bridge_test",
    use_tmpfs = True,
)

syscall_test(
    size = "small",
    container = True,
    overlay = True,
    save = False,
    test = "//test/rtnetlink/linux:setlink_test",
    use_tmpfs = True,
)

syscall_test(
    size = "small",
    container = True,
    overlay = True,
    save = False,
    test = "//test/rtnetlink/linux:route_test",
    use_tmpfs = True,
)
