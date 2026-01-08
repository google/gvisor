"""Go rules."""

load("@bazel_gazelle//:def.bzl", _gazelle = "gazelle")
load("@bazel_skylib//lib:paths.bzl", "paths")
load("@bazel_skylib//lib:shell.bzl", "shell")
load("@io_bazel_rules_go//go:def.bzl", "GoLibrary", _go_binary = "go_binary", _go_context = "go_context", _go_library = "go_library", _go_path = "go_path", _go_test = "go_test")
load("@io_bazel_rules_go//proto:def.bzl", _go_grpc_library = "go_grpc_library", _go_proto_library = "go_proto_library")
load("//tools/bazeldefs:defs.bzl", "select_arch", "select_system")

gazelle = _gazelle

go_path = _go_path
go_cov = native.genrule

def _go_proto_or_grpc_library(go_library_func, name, **kwargs):
    if "importpath" in kwargs:
        # If importpath is explicit, pass straight through.
        go_library_func(name = name, **kwargs)
        return
    deps = []
    com_google_protobuf = "@com_google_protobuf//"
    org_golang_google_protobuf = "@org_golang_google_protobuf//"
    for d in (kwargs.pop("deps", []) or []):
        # Special cases: these protos have their Go definitions in a different
        # repository.
        if d == com_google_protobuf + ":timestamp_proto":
            deps.append(org_golang_google_protobuf + "types/known/timestamppb")
            continue
        if d == com_google_protobuf + ":any_proto":
            deps.append(org_golang_google_protobuf + "types/known/anypb")
            continue

        if "//" in d:
            repo, path = d.split("//", 1)
            deps.append(repo + "//" + path.replace("_proto", "_go_proto"))
        else:
            deps.append(d.replace("_proto", "_go_proto"))
    go_library_func(
        name = name + "_go_proto",
        importpath = "gvisor.dev/gvisor/" + native.package_name() + "/" + name + "_go_proto",
        proto = ":" + name + "_proto",
        deps = deps,
        **kwargs
    )

def go_proto_library(name, **kwargs):
    _go_proto_or_grpc_library(_go_proto_library, name, **kwargs)

def go_grpc_and_proto_libraries(name, **kwargs):
    _go_proto_or_grpc_library(_go_grpc_library, name, **kwargs)

def go_binary(name, static = False, pure = False, x_defs = None, **kwargs):
    """Build a go binary.

    Args:
        name: name of the target.
        static: build a static binary.
        pure: build without cgo.
        x_defs: additional definitions.
        **kwargs: rest of the arguments are passed to _go_binary.
    """
    if static:
        kwargs["static"] = "on"
    if pure:
        kwargs["pure"] = "on"
    gc_goopts = select({
        "//conditions:default": kwargs.pop("gc_goopts", []),
        "//tools:debug": kwargs.pop("gc_goopts", []) + ["-N", "-l"],
    })
    kwargs["gotags"] = select({
        "//conditions:default": kwargs.pop("gotags", []),
        "//tools:debug": kwargs.pop("gotags", []) + ["debug"],
    })
    _go_binary(
        name = name,
        x_defs = x_defs,
        gc_goopts = gc_goopts,
        **kwargs
    )

def go_importpath(target):
    """Returns the importpath for the target."""
    return target[GoLibrary].importpath

def go_library(name, bazel_cgo = False, bazel_cdeps = [], bazel_clinkopts = [], bazel_copts = [], **kwargs):
    """Wrapper for `go_library` rule.

    Args:
        name: name of the target.
        bazel_cgo: if True, build with cgo.
        cgo_cdeps: cgo deps to pass to `go_library`.
        cgo_clinkopts: cgo linkopts to pass to `go_library`.
        cgo_copts: cgo opts to pass to `go_library`.
        **kwargs: rest of the arguments are passed to `go_library`.
    """
    _go_library(
        name = name,
        cgo = bazel_cgo,
        cdeps = bazel_cdeps,
        copts = bazel_copts,
        clinkopts = bazel_clinkopts,
        importpath = "gvisor.dev/gvisor/" + native.package_name(),
        **kwargs
    )

def go_test(name, static = False, pure = False, library = None, **kwargs):
    """Build a go test.

    Args:
        name: name of the output binary.
        static: build a static binary.
        pure: should it be built without cgo.
        library: the library to embed.
        **kwargs: rest of the arguments to pass to _go_test.
    """
    if pure:
        kwargs["pure"] = "on"
    if static:
        kwargs["static"] = "on"
    if library:
        kwargs["embed"] = [library]
    _go_test(
        name = name,
        **kwargs
    )

def go_rule(rule, implementation, **kwargs):
    """Wraps a rule definition with Go attributes.

    Args:
      rule: rule function (typically rule or aspect).
      implementation: implementation function.
      **kwargs: other arguments to pass to rule.

    Returns:
        The result of invoking the rule.
    """
    kwargs.setdefault("attrs", dict()).update({
        "_go_context_data": attr.label(default = "@io_bazel_rules_go//:go_context_data"),
        "_stdlib": attr.label(default = "@io_bazel_rules_go//:stdlib"),
    })
    kwargs.setdefault("toolchains", []).append("@io_bazel_rules_go//go:toolchain")
    return rule(implementation, **kwargs)

def go_embed_libraries(target):
    if hasattr(target.attr, "embed"):
        return target.attr.embed
    return []

def go_context(ctx, goos = None, goarch = None):
    """Extracts a standard Go context struct.

    Args:
      ctx: the starlark context (required).
      goos: the GOOS value.
      goarch: the GOARCH value.

    Returns:
      A context Go struct with pointers to Go toolchain components.
    """

    # We don't change anything for the standard library analysis. All Go files
    # are available in all instances. Note that this includes the standard
    # library sources, which are analyzed by nogo.
    go_ctx = _go_context(ctx)
    return struct(
        env = dict(go_ctx.env, CGO_ENABLED = "0"),
        go = go_ctx.go,
        goarch = goarch or go_ctx.sdk.goarch,
        goos = goos or go_ctx.sdk.goos,
        gotags = go_ctx.tags,
        nogo_args = [],
        runfiles = depset([go_ctx.go] + go_ctx.sdk.srcs.to_list() + go_ctx.sdk.tools.to_list() + go_ctx.stdlib.libs.to_list()),
        stdlib_srcs = go_ctx.sdk.srcs,
    )

def select_goarch():
    return select_arch(amd64 = "amd64", arm64 = "arm64")

def select_goos():
    return select_system(
        linux = "linux",
        darwin = "darwin",
    )

# Defined by rules_go.
gotsan_values = None
gotsan_flag_values = {"@io_bazel_rules_go//go/config:race": "true"}

def _go_imports_impl(ctx):
    """Hermetic wrapper around goimports.

    `goimports` shells out to the `go` command (via golang.org/x/tools internal
    helpers) and therefore requires a usable `go` binary during the action.

    See:
    - https://github.com/golang/tools/blob/master/internal/gocommand/invoke.go
    - https://github.com/golang/tools/blob/master/internal/imports/fix.go
    - https://go.dev/doc/go1.19#os-exec-path
    """
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
        is_executable = True,
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
