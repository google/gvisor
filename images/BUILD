package(licenses = ["notice"])

# The images filegroup is definitely not a hermetic target, and requires Make
# to do anything meaningful with. However, this will be slurped up and used by
# the tools/installer/images.sh installer, which will ensure that all required
# images are available locally when running vm_tests.
filegroup(
    name = "images",
    srcs = glob(["**"]),
    visibility = ["//tools/installers:__pkg__"],
)
