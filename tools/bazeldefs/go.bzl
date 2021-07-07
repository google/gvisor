"""Go rules."""

load("@bazel_gazelle//:def.bzl", _gazelle = "gazelle")
load("@io_bazel_rules_go//go:def.bzl", "GoLibrary", _go_binary = "go_binary", _go_context = "go_context", _go_embed_data = "go_embed_data", _go_library = "go_library", _go_path = "go_path", _go_test = "go_test")
load("@io_bazel_rules_go//proto:def.bzl", _go_grpc_library = "go_grpc_library", _go_proto_library = "go_proto_library")
load("//tools/bazeldefs:defs.bzl", "select_arch", "select_system")

gazelle = _gazelle

go_embed_data = _go_embed_data

go_path = _go_path

bazel_worker_proto = "//tools/bazeldefs:worker_protocol_go_proto"

def _go_proto_or_grpc_library(go_library_func, name, **kwargs):
    if "importpath" in kwargs:
        # If importpath is explicit, pass straight through.
        go_library_func(name = name, **kwargs)
        return
    deps = []
    for d in (kwargs.pop("deps", []) or []):
        if d == "@com_google_protobuf//:timestamp_proto":
            # Special case: this proto has its Go definitions in a different
            # repository.
            deps.append("@org_golang_google_protobuf//" +
                        "types/known/timestamppb")
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

def go_binary(name, static = False, pure = False, x_defs = None, system_malloc = False, **kwargs):
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
    _go_binary(
        name = name,
        x_defs = x_defs,
        **kwargs
    )

def go_importpath(target):
    """Returns the importpath for the target."""
    return target[GoLibrary].importpath

def go_library(name, arch_deps = [], **kwargs):
    _go_library(
        name = name,
        importpath = "gvisor.dev/gvisor/" + native.package_name(),
        **kwargs
    )

def go_test(name, pure = False, library = None, **kwargs):
    """Build a go test.

    Args:
        name: name of the output binary.
        pure: should it be built without cgo.
        library: the library to embed.
        **kwargs: rest of the arguments to pass to _go_test.
    """
    if pure:
        kwargs["pure"] = "on"
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
    attrs = kwargs.pop("attrs", dict())
    attrs["_go_context_data"] = attr.label(default = "@io_bazel_rules_go//:go_context_data")
    attrs["_stdlib"] = attr.label(default = "@io_bazel_rules_go//:stdlib")
    toolchains = kwargs.get("toolchains", []) + ["@io_bazel_rules_go//go:toolchain"]
    return rule(implementation, attrs = attrs, toolchains = toolchains, **kwargs)

def go_embed_libraries(target):
    if hasattr(target.attr, "embed"):
        return target.attr.embed
    return []

def go_context(ctx, goos = None, goarch = None, std = False):
    """Extracts a standard Go context struct.

    Args:
      ctx: the starlark context (required).
      goos: the GOOS value.
      goarch: the GOARCH value.
      std: ignored.

    Returns:
      A context Go struct with pointers to Go toolchain components.
    """

    # We don't change anything for the standard library analysis. All Go files
    # are available in all instances. Note that this includes the standard
    # library sources, which are analyzed by nogo.
    go_ctx = _go_context(ctx)
    if goos == None:
        goos = go_ctx.sdk.goos
    elif goos != go_ctx.sdk.goos:
        fail("Internal GOOS (%s) doesn't match GoSdk GOOS (%s)." % (goos, go_ctx.sdk.goos))
    if goarch == None:
        goarch = go_ctx.sdk.goarch
    elif goarch != go_ctx.sdk.goarch:
        fail("Internal GOARCH (%s) doesn't match GoSdk GOARCH (%s)." % (goarch, go_ctx.sdk.goarch))
    return struct(
        env = go_ctx.env,
        go = go_ctx.go,
        goarch = go_ctx.sdk.goarch,
        goos = go_ctx.sdk.goos,
        gotags = go_ctx.tags,
        nogo_args = [],
        runfiles = depset([go_ctx.go] + go_ctx.sdk.srcs + go_ctx.sdk.tools + go_ctx.stdlib.libs),
        stdlib_srcs = go_ctx.sdk.srcs,
    )

def select_goarch():
    return select_arch(amd64 = "amd64", arm64 = "arm64")

def select_goos():
    return select_system(linux = "linux")
