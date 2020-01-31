load("//tools:defs.bzl", "cc_binary", "gtest")
load("//tools/images:defs.bzl", "vm_image", "vm_test")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

genrule(
    name = "zone",
    outs = ["zone.txt"],
    cmd = "gcloud config get-value compute/zone > $@",
    tags = [
        "local",
        "manual",
    ],
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
        "//tools/images/ubuntu1604",
    ],
)

vm_test(
    name = "ubuntu1604_test",
    image = ":ubuntu1604",
    targets = [":test"],
)

vm_image(
    name = "ubuntu1804",
    family = "ubuntu-1804-lts",
    project = "ubuntu-os-cloud",
    scripts = [
        "//tools/images/ubuntu1804",
    ],
)

vm_test(
    name = "ubuntu1804_test",
    image = ":ubuntu1804",
    targets = [":test"],
)
