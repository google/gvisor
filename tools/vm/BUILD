load("//tools:defs.bzl", "cc_binary", "gtest")
load("//tools/vm:defs.bzl", "vm_image", "vm_test")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

sh_binary(
    name = "zone",
    srcs = ["zone.sh"],
)

sh_binary(
    name = "builder",
    srcs = ["build.sh"],
)

sh_binary(
    name = "executer",
    srcs = ["execute.sh"],
)

cc_binary(
    name = "test",
    testonly = 1,
    srcs = ["test.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:test_main",
    ],
)

vm_image(
    name = "ubuntu1604",
    family = "ubuntu-1604-lts",
    project = "ubuntu-os-cloud",
    scripts = [
        "//tools/vm/ubuntu1604",
    ],
)

vm_image(
    name = "ubuntu1804",
    family = "ubuntu-1804-lts",
    project = "ubuntu-os-cloud",
    scripts = [
        "//tools/vm/ubuntu1804",
    ],
)

vm_test(
    name = "vm_test",
    shard_count = 2,
    targets = [":test"],
)
