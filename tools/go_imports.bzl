"""Hermetic wrapper around goimports.

`goimports` shells out to the `go` command (via golang.org/x/tools internal
helpers) and therefore requires a usable `go` binary during the action.

See:
- https://github.com/golang/tools/blob/master/internal/gocommand/invoke.go
- https://github.com/golang/tools/blob/master/internal/imports/fix.go
- https://go.dev/doc/go1.19#os-exec-path
"""

load("//tools/bazeldefs:go.bzl", "go_context", "go_rule")
load("@bazel_skylib//lib:paths.bzl", "paths")
load("@bazel_skylib//lib:shell.bzl", "shell")

def _go_imports_impl(ctx):
    go_ctx = go_context(ctx)

    src = ctx.file.src
    out = ctx.outputs.out

    goimports_tool = ctx.attr._goimports[DefaultInfo].files_to_run

    tools_path = paths.join(ctx.label.name + "_tools")

    # Use a symlink to the `go` binary to avoid exposing undeclared dependencies
    # on other binaries in the same directory in the toolchain.
    go_symlink = ctx.actions.declare_file(paths.join(tools_path, "go"))
    ctx.actions.symlink(
        output = go_symlink,
        target_file = go_ctx.go,
        is_executable = True
    )

    # Use a launcher script rather than ctx.actions.run(env=...) because we need
    # to refer to the action's runtime working directory ($PWD) to build an
    # absolute PATH entry. This matters because `goimports` locates `go` via
    # os/exec.LookPath("go") and recent Go versions refuse to execute commands
    # found via a relative PATH entry.
    #
    # See https://pkg.go.dev/os/exec#hdr-Executables_in_the_current_directory.
    goimports_launcher = ctx.actions.declare_file(paths.join(tools_path, "goimports.sh"))
    ctx.actions.write(
        output = goimports_launcher,
        is_executable = True,
        content = "PATH=$PWD/{} exec {} {} > {}".format(
            shell.quote(go_symlink.dirname),
            shell.quote(goimports_tool.executable.path),
            shell.quote(src.path),
            shell.quote(out.path),
        ),
    )

    ctx.actions.run(
        inputs = [src],
        tools = [goimports_tool, go_symlink, go_ctx.runfiles],
        outputs = [out],
        executable = goimports_launcher,
        env = go_ctx.env,
        mnemonic = "GoImports",
        progress_message = "GoImports {}".format(src.short_path),
    )

    return DefaultInfo(files = depset([out]))


_go_imports = go_rule(
    rule,
    implementation = _go_imports_impl,
    attrs = {
        "src": attr.label(mandatory = True, allow_single_file = [".go"]),
        "out": attr.output(mandatory = True),
        "_goimports": attr.label(
            default = "@org_golang_x_tools//cmd/goimports:goimports",
            executable = True,
            cfg = "exec",
        ),
    },
)


def go_imports(name, src, out):
    _go_imports(
        name = name,
        src = src,
        out = out,
    )
