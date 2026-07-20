load("//tools:arch.bzl", "select_arch")
load("//tools:defs.bzl", "pkg_deb", "pkg_tar", "version")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

pkg_tar(
    name = "debian-bin",
    srcs = [
        "//runsc",
        "//runsc/cmd/metricserver:runsc-metric-server",
        "//shim:containerd-shim-runsc-v1",
    ],
    mode = "0755",
    package_dir = "/usr/bin",
)

genrule(
    name = "debian-changelog",
    srcs = [version],
    outs = ["changelog"],
    cmd = """
version="$$(cat $(location %s))"
: "$${version:=0.0.0}"
release_date="$$(printf '%%s' "$$version" | sed -n 's/^\\([0-9]\\{4\\}\\)\\([0-9]\\{2\\}\\)\\([0-9]\\{2\\}\\).*/\\1-\\2-\\3/p')"
changelog_date=""
if [ -n "$$release_date" ]; then
  linux_date="$$(date -u -d "$$release_date" '+%%a, %%d %%b %%Y 00:00:00 +0000' 2>/dev/null || true)"
  darwin_date="$$(date -u -j -f '%%Y-%%m-%%d' "$$release_date" '+%%a, %%d %%b %%Y 00:00:00 +0000' 2>/dev/null || true)"
  changelog_date="$${linux_date:-$$darwin_date}"
fi
if [ -z "$$changelog_date" ]; then
  changelog_date="Thu, 01 Jan 1970 00:00:00 +0000"
fi
cat >"$@" <<EOF
runsc ($${version}) release; urgency=medium

  * gVisor runsc release. See https://github.com/google/gvisor/releases
    for release notes.

 -- The gVisor Authors <gvisor-dev@googlegroups.com>  $${changelog_date}
EOF
""" % version,
)

genrule(
    name = "changelog-debian-gz",
    srcs = [":debian-changelog"],
    outs = ["changelog.Debian.gz"],
    cmd = "gzip -n -c $(location :debian-changelog) >$@",
)

pkg_tar(
    name = "debian-doc",
    srcs = [":changelog-debian-gz"],
    mode = "0644",
    package_dir = "/usr/share/doc/runsc",
)

sh_test(
    name = "changelog_test",
    size = "small",
    srcs = ["changelog_test.sh"],
    args = [
        "$(location :debian-changelog)",
        "$(location :changelog-debian-gz)",
        "$(location :debian-doc)",
    ],
    data = [
        ":changelog-debian-gz",
        ":debian-changelog",
        ":debian-doc",
    ],
)

pkg_tar(
    name = "debian-data",
    extension = "tar.gz",
    deps = [
        ":debian-bin",
        ":debian-doc",
        "//shim:config",
    ],
)

pkg_deb(
    name = "debian",
    architecture = select_arch(
        amd64 = "amd64",
        arm64 = "arm64",
    ),
    changelog = ":debian-changelog",
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
