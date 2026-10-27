load("@rules_pkg//pkg:mappings.bzl", "pkg_attributes", "pkg_files")
load("//tools:defs.bzl", "go_binary", "pkg_tar")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# Include the complete contexts, including files owned by nested packages.
# tools/images.mk remains responsible for architecture selection and hashing.
filegroup(
    name = "sources",
    srcs = glob(["**"]) + [
        "//images/basic:sources",
        "//images/gpu/ollama/client:sources",
    ],
)

# Build the CUDA sample runners with the repository Go toolchain.
# Their former Docker build used CGO_ENABLED=0; preserve that link contract.
go_binary(
    name = "cuda_run_sample",
    srcs = ["gpu/cuda-tests/run_sample.go"],  # keep
    pure = True,
    static = True,
)

go_binary(
    name = "cuda_12_8_run_sample",
    srcs = ["gpu/cuda-tests-12-8/run_sample.go"],  # keep
    pure = True,
    static = True,
)

pkg_files(
    name = "image_programs",
    srcs = [
        ":cuda_12_8_run_sample",
        ":cuda_run_sample",
        "//images/gpu/ollama/client",
    ],
    attributes = pkg_attributes(mode = "0755"),
    renames = {
        ":cuda_run_sample": "gpu/cuda-tests/run_sample",
        ":cuda_12_8_run_sample": "gpu/cuda-tests-12-8/run_sample",
        "//images/gpu/ollama/client": "gpu/ollama/client/client",
    },
)

# Bazel uploads every remote input as executable. Archive metadata preserves
# context modes independently of that input-tree normalization. Keep these
# overrides aligned with tracked executable files when adding context sources.
# https://github.com/bazelbuild/bazel/blob/d84820503/src/main/java/com/google/devtools/build/lib/remote/merkletree/MerkleTree.java#L400
pkg_tar(
    name = "source_contexts",
    srcs = [
        ":image_programs",
        ":sources",
    ],
    mode = "0644",
    modes = {
        "arm-qemu/initramfs/init": "0755",
        "arm-qemu/test.sh": "0755",
        "basic/docker/start-dockerd.sh": "0755",
        "basic/fsstress/run.sh": "0755",
        "benchmarks/ruby/Dockerfile": "0755",
        "benchmarks/ruby/Gemfile": "0755",
        "benchmarks/ruby/config.ru": "0755",
        "benchmarks/ruby/index.erb": "0755",
        "benchmarks/ruby/main.rb": "0755",
        "fuse/gcs/run_test.sh": "0755",
        "gpu/cuda-tests-12-8/run_smoke.sh": "0755",
        "gpu/cuda-tests/run_smoke.sh": "0755",
        "gpu/ollama/bench/pull.sh": "0755",
        "jekyll/build.sh": "0755",
    },
    package_dir = "images",
    strip_prefix = ".",
)
