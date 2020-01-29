package(licenses = ["notice"])

# In bazel, no special support is required for loopback networking. This is
# just a dummy data target that does not change the test environment.
genrule(
    name = "loopback",
    outs = ["loopback.txt"],
    cmd = "touch $@",
    visibility = ["//visibility:public"],
)
