"""Helpers for Docker image generation."""

def _docker_image_impl(ctx):
    importer = ctx.actions.declare_file(ctx.label.name)
    importer_content = [
        "#!/bin/bash",
        "set -euo pipefail",
        "exec docker import " + " ".join([
            "-c '%s'" % attr
            for attr in ctx.attr.statements
        ]) + " " + " ".join([
            "'%s'" % f.path
            for f in ctx.files.data
        ]) + " $1",
        "",
    ]
    ctx.actions.write(importer, "\n".join(importer_content), is_executable = True)
    return [DefaultInfo(
        runfiles = ctx.runfiles(ctx.files.data),
        executable = importer,
    )]

docker_image = rule(
    implementation = _docker_image_impl,
    doc = "Tool to load a Docker image; takes a single parameter (image name).",
    attrs = {
        "statements": attr.string_list(doc = "Extra Dockerfile directives."),
        "data": attr.label_list(doc = "All image data."),
    },
    executable = True,
)
