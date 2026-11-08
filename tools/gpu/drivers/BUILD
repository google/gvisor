load("//tools:defs.bzl", "go_binary", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "drivers",
    srcs = [
        "download.go",
        "install_driver.go",
    ],
    importpath = "gvisor.dev/gvisor/tools/gpu/drivers",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/sentry/devices/nvproxy",
        "//pkg/sentry/devices/nvproxy/nvconf",
    ],
)

go_binary(
    name = "fake_installer",
    testonly = True,
    srcs = ["testdata/fake_installer.go"],
    pure = True,
)

go_test(
    name = "drivers_test",
    srcs = [
        "download_test.go",
        "install_driver_test.go",
    ],
    args = ["--fake-installer=$(rootpath :fake_installer)"],
    data = [":fake_installer"],
    embed = [":drivers"],
    rundir = ".",
    deps = [
        "//pkg/sentry/devices/nvproxy",
        "//pkg/sentry/devices/nvproxy/nvconf",
    ],
)
