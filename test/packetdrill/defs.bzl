"""Defines a rule for packetdrill test targets."""

def _packetdrill_test_impl(ctx):
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
        "%s %s --init_script %s \"$@\" -- %s\n" % (
            test_runner.short_path,
            " ".join(ctx.attr.flags),
            ctx.files._init_script[0].short_path,
            " ".join(script_paths),
        ),
    ])
    ctx.actions.write(runner, runner_content, is_executable = True)

    transitive_files = depset()
    if hasattr(ctx.attr._test_runner, "data_runfiles"):
        transitive_files = ctx.attr._test_runner.data_runfiles.files
    runfiles = ctx.runfiles(
        files = [test_runner] + ctx.files._init_script + ctx.files.scripts,
        transitive_files = transitive_files,
        collect_default = True,
        collect_data = True,
    )
    return [DefaultInfo(executable = runner, runfiles = runfiles)]

_packetdrill_test = rule(
    attrs = {
        "_test_runner": attr.label(
            executable = True,
            cfg = "exec",
            allow_files = True,
            default = "packetdrill_test.sh",
        ),
        "_init_script": attr.label(
            allow_single_file = True,
            default = "packetdrill_setup.sh",
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
    implementation = _packetdrill_test_impl,
)

PACKETDRILL_TAGS = [
    "local",
    "manual",
    "packetdrill",
]

def packetdrill_linux_test(name, **kwargs):
    if "tags" not in kwargs:
        kwargs["tags"] = PACKETDRILL_TAGS
    _packetdrill_test(
        name = name,
        flags = ["--dut_platform", "linux"],
        **kwargs
    )

def packetdrill_netstack_test(name, **kwargs):
    if "tags" not in kwargs:
        kwargs["tags"] = PACKETDRILL_TAGS
    _packetdrill_test(
        name = name,
        flags = ["--dut_platform", "netstack"],
        **kwargs
    )

def packetdrill_test(name, **kwargs):
    packetdrill_linux_test(name + "_linux_test", **kwargs)
    packetdrill_netstack_test(name + "_netstack_test", **kwargs)
