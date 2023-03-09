load("//tools:defs.bzl", "cc_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

cc_binary(
    name = "server_cc",
    srcs = ["server.cc"],
    # gcc reports the false warning:
    # examples/seccheck/server.cc:147:19: error: 'buf' may be used uninitialized
    # More details are here:
    # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=101831
    copts = [
        "-Wno-maybe-uninitialized",
        "-Wno-unknown-warning-option",
    ],
    visibility = ["//:sandbox"],
    deps = [
        # any_cc_proto placeholder,
        "//pkg/sentry/seccheck/points:points_cc_proto",
        "@com_google_absl//absl/cleanup",
        "@com_google_absl//absl/strings",
    ],
)
