"""Defines a rule for runtime test targets."""

load("//tools:defs.bzl", "go_test")

def _runtime_test_impl(ctx):
    # Construct arguments.
    args = [
        "--lang",
        ctx.attr.lang,
        "--image",
        ctx.attr.image,
        "--batch",
        str(ctx.attr.batch),
    ]
    if ctx.attr.exclude_file:
        args += [
            "--exclude_file",
            ctx.files.exclude_file[0].short_path,
        ]

    # Build a runner.
    runner = ctx.actions.declare_file("%s-executer" % ctx.label.name)
    runner_content = "\n".join([
        "#!/bin/bash",
        "%s %s $@\n" % (ctx.files._runner[0].short_path, " ".join(args)),
    ])
    ctx.actions.write(runner, runner_content, is_executable = True)

    # Return the runner.
    return [DefaultInfo(
        executable = runner,
        runfiles = ctx.runfiles(
            files = ctx.files._runner + ctx.files.exclude_file + ctx.files._proctor,
            collect_default = True,
            collect_data = True,
        ),
    )]

_runtime_test = rule(
    implementation = _runtime_test_impl,
    attrs = {
        "image": attr.string(
            mandatory = False,
        ),
        "lang": attr.string(
            mandatory = True,
        ),
        "exclude_file": attr.label(
            mandatory = False,
            allow_single_file = True,
        ),
        "batch": attr.int(
            default = 50,
            mandatory = False,
        ),
        "_runner": attr.label(
            default = "//test/runtimes/runner:runner",
            executable = True,
            cfg = "target",
        ),
        "_proctor": attr.label(
            default = "//test/runtimes/proctor:proctor",
            executable = True,
            cfg = "target",
        ),
    },
    test = True,
)

def runtime_test(name, **kwargs):
    _runtime_test(
        name = name,
        image = name,  # Resolved as images/runtimes/%s.
        tags = [
            "local",
            "manual",
        ],
        **kwargs
    )

def exclude_test(name, exclude_file):
    """Test that a exclude file parses correctly."""
    go_test(
        name = name + "_exclude_test",
        library = ":runner",
        srcs = ["exclude_test.go"],
        args = ["--exclude_file", "test/runtimes/" + exclude_file],
        data = [exclude_file],
    )
