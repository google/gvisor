"""C programs shipped alongside runsc that run without a C runtime."""

load("//tools:arch.bzl", "transition_allowlist")
load("//tools:defs.bzl", "cc_binary")

def _sidecar_options(settings, _attr):
    # --custom_malloc overrides cc_binary's malloc attribute. These programs
    # issue syscalls directly and cannot link an allocator or sanitizer runtime.
    return {
        "//command_line_option:custom_malloc": str(Label("@bazel_tools//tools/cpp:malloc")),
        "//command_line_option:linkopt": settings["//command_line_option:linkopt"] + ["-fno-sanitize=all"],
    }

_sidecar_transition = transition(
    implementation = _sidecar_options,
    inputs = ["//command_line_option:linkopt"],
    outputs = ["//command_line_option:custom_malloc", "//command_line_option:linkopt"],
)

def _sidecar_executable_impl(ctx):
    [binary] = ctx.files.binary
    ctx.actions.symlink(output = ctx.outputs.out, target_file = binary, is_executable = True)
    return [DefaultInfo(executable = ctx.outputs.out)]

_sidecar_executable = rule(
    implementation = _sidecar_executable_impl,
    executable = True,
    attrs = {
        "binary": attr.label(allow_single_file = True, cfg = _sidecar_transition, mandatory = True),
        "out": attr.output(mandatory = True),
        "_allowlist_function_transition": attr.label(default = transition_allowlist),
    },
)

def freestanding_sidecar(name, src, out):
    """Builds a static executable with its own process entry point.

    Args:
      name: Public Bazel target for the sidecar.
      src: C source file defining _start.
      out: Filename used by runsc and the sidecar tests.
    """
    cc_binary(
        name = "_linked/" + out,
        srcs = [src],
        copts = [
            "-Os",
            "-ffreestanding",
            "-fno-pie",
            "-fno-sanitize=all",
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-fno-unwind-tables",
        ],
        # These executables have their own entry point and use only syscalls.
        # Do not add either toolchain's hosted libraries or startup code.
        features = [
            "-coverage",
            "-default_link_flags",
            "-default_linker_libraries",
            "-heap_partitioning",
            "-pie",
            "-static_link_cpp_runtimes",
            "-static_linking_mode",
            "-use_header_modules",
            "-use_pthread",
        ],
        linkopts = [
            "-static",
            "-nostdlib",
            "-nostartfiles",
            "-Wl,--build-id=none",
            "-Wl,--gc-sections",
            # Avoid padding loadable segments to a page boundary.
            "-Wl,-n",
            "-Wl,-s",
        ],
        linkstatic = True,
        stamp = 0,
        tcmalloc = False,
        visibility = ["//visibility:private"],
    )
    _sidecar_executable(
        name = name,
        binary = ":_linked/" + out,
        out = out,
        visibility = ["//visibility:public"],
    )
