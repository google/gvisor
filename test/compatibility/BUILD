load("//tools:defs.bzl", "go_library")
load(":defs.bzl", "compatibility_test")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_library(
    name = "compatibility",
    testonly = True,
    srcs = ["compatibility.go"],
)

compatibility_test(
    name = "gitea",
    srcs = ["gitea/gitea_test.go"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/compatibility",
    ],
)

compatibility_test(
    name = "nextcloud",
    srcs = ["nextcloud/nextcloud_test.go"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/compatibility",
    ],
)

compatibility_test(
    name = "wordpress",
    srcs = ["wordpress/wordpress_test.go"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/compatibility",
    ],
)
