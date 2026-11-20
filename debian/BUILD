load("//tools:arch.bzl", "select_arch")
load("//tools:defs.bzl", "pkg_deb", "pkg_tar", "version")
load("//tools:release.bzl", "SIDECARS", "release_tars")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

pkg_tar(
    name = "debian-gvisor-bin",
    files = SIDECARS,
    mode = "0755",
    package_dir = "/usr/bin/gvisor-bin",
)

pkg_tar(
    name = "debian-bin",
    srcs = [
        "//runsc",
        "//shim:containerd-shim-runsc-v1",
    ],
    mode = "0755",
    package_dir = "/usr/bin",
)

pkg_tar(
    name = "debian-data",
    extension = "tar.gz",
    deps = [
        ":debian-bin",
        ":debian-gvisor-bin",
        "//shim:config",
    ],
)

genrule(
    name = "changelog",
    srcs = ["//tools/bazeldefs:version"],
    outs = ["changelog"],
    cmd = "VERSION=$$(cat $(location //tools/bazeldefs:version)); printf 'runsc (%s) unstable; urgency=medium\\n\\n  * See https://gvisor.dev/docs/ for release details.\\n\\n -- The gVisor Authors <gvisor-dev@googlegroups.com>  %s\\n' \"$$VERSION\" \"$$(date -R)\" > \"$@\"",
    stamp = 1,
)

pkg_deb(
    name = "debian",
    architecture = select_arch(
        amd64 = "amd64",
        arm64 = "arm64",
    ),
    changelog = ":changelog",
    conffiles = [
        "/etc/containerd/runsc.toml",
    ],
    data = ":debian-data",
    # Note that the description_file will be flatten (all newlines removed),
    # and therefore it is kept to a simple one-line description. The expected
    # format for debian packages is "short summary\nLonger explanation of
    # tool." and this is impossible with the flattening.
    description_file = "description",
    homepage = "https://gvisor.dev/",
    maintainer = "The gVisor Authors <gvisor-dev@googlegroups.com>",
    package = "runsc",
    package_file_name = "runsc.deb",
    postinst = "postinst.sh",
    version_file = version,
    visibility = [
        "//visibility:public",
    ],
)

# The containerd shim must be at the top level because containerd finds it
# through PATH. runsc finds its sidecars under gvisor-bin next to itself.
RELEASE_TAR_EXTRA_BINS = {
    "//shim:containerd-shim-runsc-v1": "containerd-shim-runsc-v1",
}

# Downloadable bzip2 and zstd archives of the uninstrumented release.
release_tars(
    name = "gvisor-release",
    basename = "gvisor",
    bins = RELEASE_TAR_EXTRA_BINS,
    flavor = "default",
    visibility = ["//visibility:public"],
)

# Release tarballs of instrumented gVisor builds, for fuzzing and testing.
# Same installed paths as the regular release tarballs.

# Go coverage instrumentation (kcov), e.g. for syzkaller.
release_tars(
    name = "gvisor-release-coverage",
    bins = RELEASE_TAR_EXTRA_BINS,
    flavor = "coverage",
)

# Go race detector.
release_tars(
    name = "gvisor-release-race",
    bins = RELEASE_TAR_EXTRA_BINS,
    flavor = "race",
)

# Go coverage instrumentation (kcov) and race detector.
release_tars(
    name = "gvisor-release-race-coverage",
    bins = RELEASE_TAR_EXTRA_BINS,
    flavor = "race-coverage",
)
