"""Defines rules for packetimpact test targets."""

load("//tools:defs.bzl", "go_test")

def _packetimpact_test_impl(ctx):
    test_runner = ctx.executable._test_runner
    bench = ctx.actions.declare_file("%s-bench" % ctx.label.name)
    bench_content = "\n".join([
        "#!/bin/bash",
        # This test will run part in a distinct user namespace. This can cause
        # permission problems, because all runfiles may not be owned by the
        # current user, and no other users will be mapped in that namespace.
        # Make sure that everything is readable here.
        "find . -type f -or -type d -exec chmod a+rx {} \\;",
        "%s %s --testbench_binary %s $@\n" % (
            test_runner.short_path,
            " ".join(ctx.attr.flags),
            ctx.files.testbench_binary[0].short_path,
        ),
    ])
    ctx.actions.write(bench, bench_content, is_executable = True)

    transitive_files = []
    if hasattr(ctx.attr._test_runner, "data_runfiles"):
        transitive_files.append(ctx.attr._test_runner.data_runfiles.files)
    runfiles = ctx.runfiles(
        files = [test_runner] + ctx.files.testbench_binary + ctx.files._posix_server_binary,
        transitive_files = depset(transitive = transitive_files),
        collect_default = True,
        collect_data = True,
    )
    return [DefaultInfo(executable = bench, runfiles = runfiles)]

_packetimpact_test = rule(
    attrs = {
        "_test_runner": attr.label(
            executable = True,
            cfg = "target",
            default = ":packetimpact_test",
        ),
        "_posix_server_binary": attr.label(
            cfg = "target",
            default = "//test/packetimpact/dut:posix_server",
        ),
        "testbench_binary": attr.label(
            cfg = "target",
            mandatory = True,
        ),
        "flags": attr.string_list(
            mandatory = False,
            default = [],
        ),
    },
    test = True,
    implementation = _packetimpact_test_impl,
)

PACKETIMPACT_TAGS = ["local", "manual"]

def packetimpact_linux_test(
        name,
        testbench_binary,
        expect_failure = False,
        **kwargs):
    """Add a packetimpact test on linux.

    Args:
        name: name of the test
        testbench_binary: the testbench binary
        expect_failure: the test must fail
        **kwargs: all the other args, forwarded to _packetimpact_test
    """
    expect_failure_flag = ["--expect_failure"] if expect_failure else []
    _packetimpact_test(
        name = name + "_linux_test",
        testbench_binary = testbench_binary,
        flags = ["--dut_platform", "linux"] + expect_failure_flag,
        tags = PACKETIMPACT_TAGS + ["packetimpact"],
        **kwargs
    )

def packetimpact_netstack_test(
        name,
        testbench_binary,
        expect_failure = False,
        **kwargs):
    """Add a packetimpact test on netstack.

    Args:
        name: name of the test
        testbench_binary: the testbench binary
        expect_failure: the test must fail
        **kwargs: all the other args, forwarded to _packetimpact_test
    """
    expect_failure_flag = []
    if expect_failure:
        expect_failure_flag = ["--expect_failure"]
    _packetimpact_test(
        name = name + "_netstack_test",
        testbench_binary = testbench_binary,
        # This is the default runtime unless
        # "--test_arg=--runtime=OTHER_RUNTIME" is used to override the value.
        flags = ["--dut_platform", "netstack", "--runtime=runsc-d"] + expect_failure_flag,
        tags = PACKETIMPACT_TAGS + ["packetimpact"],
        **kwargs
    )

def packetimpact_go_test(name, size = "small", pure = True, expect_linux_failure = False, expect_netstack_failure = False, **kwargs):
    """Add packetimpact tests written in go.

    Args:
        name: name of the test
        size: size of the test
        pure: make a static go binary
        expect_linux_failure: the test must fail for Linux
        expect_netstack_failure: the test must fail for Netstack
        **kwargs: all the other args, forwarded to go_test
    """
    testbench_binary = name + "_test"
    go_test(
        name = testbench_binary,
        size = size,
        pure = pure,
        tags = PACKETIMPACT_TAGS,
        **kwargs
    )
    packetimpact_linux_test(
        name = name,
        expect_failure = expect_linux_failure,
        testbench_binary = testbench_binary,
    )
    packetimpact_netstack_test(
        name = name,
        expect_failure = expect_netstack_failure,
        testbench_binary = testbench_binary,
    )
