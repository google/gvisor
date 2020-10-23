"""Helpers for Docker image generation."""

def _docker_image_impl(ctx):
    importer = ctx.actions.declare_file(ctx.label.name)

    importer_content = [
        "#!/bin/bash",
        "set -euo pipefail",
        "source_file='%s'" % ctx.file.data.path,
        "if [[ ! -f \"$source_file\" ]]; then",
        "  source_file='%s'" % ctx.file.data.short_path,
        "fi",
        "exec docker import " + " ".join([
            "-c '%s'" % attr
            for attr in ctx.attr.statements
        ]) + " \"$source_file\" $1",
        "",
    ]

    ctx.actions.write(importer, "\n".join(importer_content), is_executable = True)
    return [DefaultInfo(
        runfiles = ctx.runfiles([ctx.file.data]),
        executable = importer,
    )]

docker_image = rule(
    implementation = _docker_image_impl,
    doc = "Tool to import a Docker image; takes a single parameter (image name).",
    attrs = {
        "statements": attr.string_list(doc = "Extra Dockerfile directives."),
        "data": attr.label(doc = "Image filesystem tarball", allow_single_file = [".tgz", ".tar.gz"]),
    },
    executable = True,
)
