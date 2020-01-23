"""Defines a rule for packetimpact test targets."""

def _packetimpact_test_impl(ctx):
    test_runner = ctx.executable._test_runner
    runner = ctx.actions.declare_file("%s-runner" % ctx.label.name)

    script_paths = []
    for script in ctx.files.scripts:
        script_paths.append(script.short_path)
    runner_content = "\n".join([
        "#!/bin/bash",
        # This test will run part in a distinct user namespace. This can cause
        # permission problems, because all runfiles may not be owned by the
        # current user, and no other users will be mapped in that namespace.
        # Make sure that everything is readable here.
        "find . -type f -exec chmod a+rx {} \\;",
        "find . -type d -exec chmod a+rx {} \\;",
        "%s %s --stub %s --test_runner_py %s $@ -- %s\n" % (
            test_runner.short_path,
            " ".join(ctx.attr.flags),
            ctx.files._stub_cc[0].short_path,
            ctx.files._test_runner_py[0].short_path,
            " ".join(script_paths),
        ),
    ])
    ctx.actions.write(runner, runner_content, is_executable = True)

    transitive_files = depset()
    if hasattr(ctx.attr._test_runner, "data_runfiles"):
        transitive_files = depset(ctx.attr._test_runner.data_runfiles.files)
    runfiles = ctx.runfiles(
        files = [test_runner] + ctx.files._stub_cc + ctx.files._test_runner_py + ctx.files.scripts,
        transitive_files = transitive_files,
        collect_default = True,
        collect_data = True,
    )
    return [DefaultInfo(executable = runner, runfiles = runfiles)]

_packetimpact_test = rule(
    attrs = {
        "_test_runner": attr.label(
            executable = True,
            cfg = "host",
            allow_files = True,
            default = "packetimpact_test.sh",
        ),
        "_stub_cc": attr.label(
            allow_single_file = True,
            cfg = "host",
            default = "stub.cc",
        ),
        "_test_runner_py": attr.label(
            allow_single_file = True,
            cfg = "host",
            default = "test_runner.py",
        ),
        "flags": attr.string_list(
            mandatory = False,
            default = [],
        ),
        "scripts": attr.label_list(
            mandatory = True,
            allow_files = True,
        ),
    },
    test = True,
    implementation = _packetimpact_test_impl,
)

_PACKETIMPACT_TAGS = ["local", "manual"]

def packetimpact_linux_test(name, **kwargs):
    if "tags" not in kwargs:
        kwargs["tags"] = _PACKETIMPACT_TAGS
    _packetimpact_test(
        name = name + "_linux_test",
        flags = ["--dut_platform", "linux"],
        **kwargs
    )

def packetimpact_netstack_test(name, **kwargs):
    if "tags" not in kwargs:
        kwargs["tags"] = _PACKETIMPACT_TAGS
    _packetimpact_test(
        name = name + "_netstack_test",
        # This is the default runtime unless
        # "--test_arg=--runtime=OTHER_RUNTIME" is used to override the value.
        flags = ["--dut_platform", "netstack", "--runtime", "runsc-d"],
        **kwargs
    )

def packetimpact_test(**kwargs):
    packetimpact_linux_test(**kwargs)
    packetimpact_netstack_test(**kwargs)
