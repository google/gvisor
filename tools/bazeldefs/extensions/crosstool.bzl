"""Module extension for the crosstool repository."""

load("@coral_crosstool//:configure.bzl", "cc_crosstool")

def _crosstool_impl(ctx):
    cc_crosstool(
        name = "crosstool",
        c_version = "gnu17",
    )

crosstool_extension = module_extension(
    implementation = _crosstool_impl,
)
