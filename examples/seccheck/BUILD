load("//tools:defs.bzl", "cc_binary")

package(licenses = ["notice"])

cc_binary(
    name = "server_cc",
    srcs = ["server.cc"],
    visibility = ["//:sandbox"],
    deps = [
        # any_cc_proto placeholder,
        "//pkg/sentry/seccheck/points:points_cc_proto",
        "@com_google_absl//absl/cleanup",
        "@com_google_absl//absl/strings",
    ],
)
