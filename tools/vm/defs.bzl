"""Image configuration. See README.md."""

load("//tools:defs.bzl", "default_installer")

# vm_image_builder is a rule that will construct a shell script that actually
# generates a given VM image. Note that this does not _run_ the shell script
# (although it can be run manually). It will be run manually during generation
# of the vm_image target itself. This level of indirection is used so that the
# build system itself only runs the builder once when multiple targets depend
# on it, avoiding a set of races and conflicts.
def _vm_image_builder_impl(ctx):
    # Generate a binary that actually builds the image.
    builder = ctx.actions.declare_file(ctx.label.name)
    script_paths = []
    for script in ctx.files.scripts:
        script_paths.append(script.short_path)
    builder_content = "\n".join([
        "#!/bin/bash",
        "export ZONE=$(%s)" % ctx.files.zone[0].short_path,
        "export USERNAME=%s" % ctx.attr.username,
        "export IMAGE_PROJECT=%s" % ctx.attr.project,
        "export IMAGE_FAMILY=%s" % ctx.attr.family,
        "%s %s" % (ctx.files._builder[0].short_path, " ".join(script_paths)),
        "",
    ])
    ctx.actions.write(builder, builder_content, is_executable = True)

    # Note that the scripts should only be files, and should not include any
    # indirect transitive dependencies. The build script wouldn't work.
    return [DefaultInfo(
        executable = builder,
        runfiles = ctx.runfiles(
            files = ctx.files.scripts + ctx.files._builder + ctx.files.zone,
        ),
    )]

vm_image_builder = rule(
    attrs = {
        "_builder": attr.label(
            executable = True,
            default = "//tools/vm:builder",
            cfg = "host",
        ),
        "username": attr.string(default = "$(whoami)"),
        "zone": attr.label(
            executable = True,
            default = "//tools/vm:zone",
            cfg = "host",
        ),
        "family": attr.string(mandatory = True),
        "project": attr.string(mandatory = True),
        "scripts": attr.label_list(allow_files = True),
    },
    executable = True,
    implementation = _vm_image_builder_impl,
)

# See vm_image_builder above.
def _vm_image_impl(ctx):
    # Run the builder to generate our output.
    echo = ctx.actions.declare_file(ctx.label.name)
    resolved_inputs, argv, runfiles_manifests = ctx.resolve_command(
        command = "\n".join([
            "set -e",
            "image=$(%s)" % ctx.files.builder[0].path,
            "echo -ne \"#!/bin/bash\\necho ${image}\\n\" > %s" % echo.path,
            "chmod 0755 %s" % echo.path,
        ]),
        tools = [ctx.attr.builder],
    )
    ctx.actions.run_shell(
        tools = resolved_inputs,
        outputs = [echo],
        progress_message = "Building image...",
        execution_requirements = {"local": "true"},
        command = argv,
        input_manifests = runfiles_manifests,
    )

    # Return just the echo command. All of the builder runfiles have been
    # resolved and consumed in the generation of the trivial echo script.
    return [DefaultInfo(executable = echo)]

_vm_image_test = rule(
    attrs = {
        "builder": attr.label(
            executable = True,
            cfg = "host",
        ),
    },
    test = True,
    implementation = _vm_image_impl,
)

def vm_image(name, **kwargs):
    vm_image_builder(
        name = name + "_builder",
        **kwargs
    )
    _vm_image_test(
        name = name,
        builder = ":" + name + "_builder",
        tags = [
            "local",
            "manual",
        ],
    )

def _vm_test_impl(ctx):
    runner = ctx.actions.declare_file("%s-executer" % ctx.label.name)

    # Note that the remote execution case must actually generate an
    # intermediate target in order to collect all the relevant runfiles so that
    # they can be copied over for remote execution.
    runner_content = "\n".join([
        "#!/bin/bash",
        "export ZONE=$(%s)" % ctx.files.zone[0].short_path,
        "export USERNAME=%s" % ctx.attr.username,
        "export IMAGE=$(%s)" % ctx.files.image[0].short_path,
        "export SUDO=%s" % "true" if ctx.attr.sudo else "false",
        "%s %s" % (
            ctx.executable.executer.short_path,
            " ".join([
                target.files_to_run.executable.short_path
                for target in ctx.attr.targets
            ]),
        ),
        "",
    ])
    ctx.actions.write(runner, runner_content, is_executable = True)

    # Return with all transitive files.
    runfiles = ctx.runfiles(
        transitive_files = depset(transitive = [
            depset(target.data_runfiles.files)
            for target in ctx.attr.targets
            if hasattr(target, "data_runfiles")
        ]),
        files = ctx.files.executer + ctx.files.zone + ctx.files.image +
                ctx.files.targets,
        collect_default = True,
        collect_data = True,
    )
    return [DefaultInfo(executable = runner, runfiles = runfiles)]

_vm_test = rule(
    attrs = {
        "image": attr.label(
            executable = True,
            default = "//tools/vm:ubuntu1804",
            cfg = "host",
        ),
        "executer": attr.label(
            executable = True,
            default = "//tools/vm:executer",
            cfg = "host",
        ),
        "username": attr.string(default = "$(whoami)"),
        "zone": attr.label(
            executable = True,
            default = "//tools/vm:zone",
            cfg = "host",
        ),
        "sudo": attr.bool(default = True),
        "machine": attr.string(default = "n1-standard-1"),
        "targets": attr.label_list(
            mandatory = True,
            allow_empty = False,
            cfg = "target",
        ),
    },
    test = True,
    implementation = _vm_test_impl,
)

def vm_test(
        installers = None,
        **kwargs):
    """Runs the given targets as a remote test.

    Args:
      installer: Script to run before all targets.
      **kwargs: All test arguments. Should include targets and image.
    """
    targets = kwargs.pop("targets", [])
    if installers == None:
        installers = [
            "//tools/installers:head",
            "//tools/installers:images",
        ]
    targets = installers + targets
    if default_installer():
        targets = [default_installer()] + targets
    _vm_test(
        tags = [
            "local",
            "manual",
        ],
        targets = targets,
        local = 1,
        **kwargs
    )
