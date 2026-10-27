"""C programs shipped alongside runsc that run without a C runtime."""

load("//tools:defs.bzl", "cc_binary")

def freestanding_sidecar(name, src, out):
    """Builds a static executable with its own process entry point.

    Args:
      name: Public Bazel target for the sidecar.
      src: C source file defining _start.
      out: Filename used by runsc and the sidecar tests.
    """
    cc_binary(
        name = out,
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
        # The toolchain's default link flags would add the C++ and math libraries.
        features = ["-coverage", "-default_link_flags", "-pie"],
        link_extra_lib = None,
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
        visibility = ["//visibility:public"],
    )
    native.alias(
        name = name,
        actual = ":" + out,
        visibility = ["//visibility:public"],
    )
