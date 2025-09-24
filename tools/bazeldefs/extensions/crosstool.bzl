"""Module extension for the crosstool repository."""

load("@coral_crosstool//:configure.bzl", "cc_crosstool")


crosstool_extension = module_extension(
    implementation = lambda mctx: cc_crosstool(name = "crosstool", c_version = "gnu17"),
)
