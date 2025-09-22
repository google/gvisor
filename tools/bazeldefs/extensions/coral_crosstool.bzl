"""Module extension for the coral_crosstool repository."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def _crosstool_impl(ctx):
    http_archive(
        name = "coral_crosstool",
        patch_args = ["-p1"],
        patches = [
            "//tools:crosstool-arm-dirs.patch",
            "//tools:remove_windows_deps.patch",
        ],
        sha256 = "f86d488ca353c5ee99187579fe408adb73e9f2bb1d69c6e3a42ffb904ce3ba01",
        strip_prefix = "crosstool-8e885509123395299bed6a5f9529fdc1b9751599",
        urls = [
            "https://github.com/google-coral/crosstool/archive/8e885509123395299bed6a5f9529fdc1b9751599.tar.gz",
        ],
    )

coral_crosstool_extension = module_extension(
    implementation = _crosstool_impl,
)
