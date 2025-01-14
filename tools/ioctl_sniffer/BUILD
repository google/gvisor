load("//tools:defs.bzl", "cc_binary", "go_binary", "proto_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

proto_library(
    name = "ioctl",
    srcs = ["ioctl.proto"],
    visibility = ["//tools/ioctl_sniffer:__subpackages__"],
)

cc_binary(
    name = "ioctl_hook",
    srcs = [
        "ioctl_hook.cc",
        "ioctl_hook.h",
        "sniffer_bridge.cc",
        "sniffer_bridge.h",
    ],
    # Needed to support being used when LD_PRELOAD'd into binaries that are
    # built with a libc library that doesn't support RELR relocations
    # (such as nvidia-smi).
    features = ["-enable_relr"],
    linkshared = True,
    deps = [
        ":ioctl_cc_proto",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_protobuf//src/google/protobuf/io",
    ],
)

go_binary(
    name = "run_sniffer",
    srcs = [
        "ld.go",
        "run_sniffer.go",
    ],
    embedsrcs = [
        # The 'keep' comment is needed to prevent glaze from removing this
        # dependency. This is because the `:ioctl_hook` `cc_binary` rule
        # output file is 'libioctl_hook.so' (because of `linkshared = True`),
        # but glaze assumes that the output file is just `ioctl_hook`, so it
        # can't associate the `go:embed` statement in `run_sniffer.go` with
        # `:ioctl_hook`'s actual output file.
        ":ioctl_hook",  # keep
    ],
    features = ["fully_static_link"],
    # Disable nogo tests because this has C++ dependencies.
    nogo = False,
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/log",
        "//tools/ioctl_sniffer/sniffer",
    ],
)
