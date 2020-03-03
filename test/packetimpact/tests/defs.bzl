"""Defines rules for packetimpact test targets."""

load("//tools:defs.bzl", "go_test")

def _packetimpact_test_impl(ctx):
    testbench = ctx.executable._testbench
    bench = ctx.actions.declare_file("%s-bench" % ctx.label.name)
    bench_content = "\n".join([
        "#!/bin/bash",
        # This test will run part in a distinct user namespace. This can cause
        # permission problems, because all runfiles may not be owned by the
        # current user, and no other users will be mapped in that namespace.
        # Make sure that everything is readable here.
        "find . -type f -exec chmod a+rx {} \\;",
        "find . -type d -exec chmod a+rx {} \\;",
        "%s %s --stub_binary %s --test_binary %s $@\n" % (
            testbench.short_path,
            " ".join(ctx.attr.flags),
            ctx.files._stub_binary[0].short_path,
            ctx.files.test_binary[0].short_path,
        ),
    ])
    ctx.actions.write(bench, bench_content, is_executable = True)

    transitive_files = depset()
    if hasattr(ctx.attr._testbench, "data_runfiles"):
        transitive_files = depset(ctx.attr._testbench.data_runfiles.files)
    runfiles = ctx.runfiles(
        files = [testbench] + ctx.files.test_binary + ctx.files._stub_binary,
        transitive_files = transitive_files,
        collect_default = True,
        collect_data = True,
    )
    return [DefaultInfo(executable = bench, runfiles = runfiles)]

_packetimpact_test = rule(
    attrs = {
        "_testbench": attr.label(
            executable = True,
            cfg = "target",
            allow_files = True,
            default = "packetimpact_test.sh",
        ),
        "_stub_binary": attr.label(
            allow_single_file = True,
            cfg = "target",
            default = "//test/packetimpact/stub:stub",
        ),
        "test_binary": attr.label(
            allow_single_file = True,
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

def packetimpact_linux_test(name, test_binary, **kwargs):
    """Add a packetimpact test on linux.

    Args:
        name: name of the test
        test_binary: the testbench binary
        **kwargs: all the other args, forwarded to _packetimpact_test
    """
    _packetimpact_test(
        name = name + "_linux_test",
        test_binary = test_binary,
        flags = ["--dut_platform", "linux"],
        tags = PACKETIMPACT_TAGS,
        **kwargs
    )

def packetimpact_netstack_test(name, test_binary, **kwargs):
    """Add a packetimpact test on netstack.

    Args:
        name: name of the test
        test_binary: the testbench binary
        **kwargs: all the other args, forwarded to _packetimpact_test
    """
    _packetimpact_test(
        name = name + "_netstack_test",
        test_binary = test_binary,
        # This is the default runtime unless
        # "--test_arg=--runtime=OTHER_RUNTIME" is used to override the value.
        flags = ["--dut_platform", "netstack", "--runtime", "runsc-d"],
        tags = PACKETIMPACT_TAGS,
        **kwargs
    )

def packetimpact_go_test(name, size = "small", pure = True, **kwargs):
    test_binary = name + "_test"
    go_test(
        name = test_binary,
        size = size,
        pure = pure,
        tags = PACKETIMPACT_TAGS,
        **kwargs
    )
    packetimpact_linux_test(name = name, test_binary = test_binary)
    packetimpact_netstack_test(name = name, test_binary = test_binary)
