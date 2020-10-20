"""Helpers for Docker image generation."""

def _docker_image_impl(ctx):
    importer = ctx.actions.declare_file(ctx.label.name)
    importer_content = [
        "#!/bin/bash",
        "set -xeuo pipefail",
        "declare source_file",
        "if [[ -f '%s' ]]; then" % f.path,
        "  source_file='%s';" % f.path,
        "else",
        "  source_file='%s';" % f.short_path,
        "fi",
    ]
    importer_content.append("exec docker import \\")
    for attr in ctx.attr.statements:
        importer_content.append("  -c '%s' \\" % attr)
    importer_content.append("  \"${source_file}\" $1\n")
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
        "data": attr.label_list(
            doc = "Image data tarball.",
            allow_single_file = [".tgz", ".tar.gz"],
        ),
    },
    executable = True,
)
