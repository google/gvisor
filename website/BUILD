load("//tools:defs.bzl", "bzl_library", "pkg_tar")
load("//website:defs.bzl", "doc", "docs")
load("//images:defs.bzl", "docker_image")

package(licenses = ["notice"])

docker_image(
    name = "website",
    data = ":files",
    statements = [
        "EXPOSE 8080/tcp",
        'ENTRYPOINT ["/server"]',
    ],
)

# files is the full file system of the generated container.
#
# It must collect the all tarballs (produced by the rules below), and run it
# through the Dockerfile to generate the site. Note that this checks all links,
# and therefore requires all static content to be present as well.
#
# Note that this rule violates most aspects of hermetic builds. However, this
# works much more reliably than depending on the container_image rules from
# bazel itself, which are convoluted and seem to have a hard time even finding
# the toolchain.
genrule(
    name = "files",
    srcs = [
        ":config",
        ":css",
        ":docs",
        ":static",
        ":syscallmd",
        "//website/blog:posts",
        "//website/cmd/server",
    ],
    outs = ["files.tgz"],
    cmd = "set -x; " +
          "T=$$(mktemp -d); " +
          "mkdir -p $$T/input && " +
          "mkdir -p $$T/output/_site && " +
          "tar -xf $(location :config)    -C $$T/input && " +
          "tar -xf $(location :css)       -C $$T/input && " +
          "tar -xf $(location :docs)      -C $$T/input && " +
          "tar -xf $(location :syscallmd) -C $$T/input && " +
          "tar -xf $(location //website/blog:posts) -C $$T/input && " +
          "find $$T/input -type f -exec chmod u+rw {} \\; && " +
          "docker run -i --user $$(id -u):$$(id -g) " +
          "-v $$(readlink -m $$T/input):/input " +
          "-v $$(readlink -m $$T/output/_site):/output " +
          "gvisor.dev/images/jekyll && " +
          "tar -xf $(location :static) -C $$T/output/_site && " +
          "docker run -i --user $$(id -u):$$(id -g) " +
          "-v $$(readlink -m $$T/output/_site):/output " +
          "gvisor.dev/images/jekyll " +
          "ruby /checks.rb " +
          "/output && " +
          "cp $(location //website/cmd/server) $$T/output/server && " +
          "tar -zcf $@ -C $$T/output . && " +
          "rm -rf $$T",
    tags = [
        "local",
        "manual",
        "nosandbox",
    ],
)

# static are the purely static parts of the site. These are effectively copied
# in after jekyll generates all the dynamic content.
pkg_tar(
    name = "static",
    srcs = [
        "archive.key",
    ] + glob([
        "performance/**",
    ]),
    strip_prefix = "./",
)

# main.scss requires front-matter to be processed.
genrule(
    name = "css",
    srcs = glob([
        "css/**",
    ]),
    outs = [
        "css.tar",
    ],
    cmd = "T=$$(mktemp -d); " +
          "mkdir -p $$T/css && " +
          "for file in $(SRCS); do " +
          "echo -en '---\\n---\\n' > $$T/css/$$(basename $$file) && " +
          "cat $$file >> $$T/css/$$(basename $$file); " +
          "done && " +
          "tar -C $$T -czf $@ . && " +
          "rm -rf $$T",
)

# config is "mostly" static content. These are parts of the site that are
# present when jekyll runs, but are not dynamically generated.
pkg_tar(
    name = "config",
    srcs = [
        ":css",
        "_config.yml",
        "//website/blog:index.html",
    ] + glob([
        "assets/**",
        "_includes/**",
        "_layouts/**",
        "_plugins/**",
        "_sass/**",
    ]),
    strip_prefix = "./",
)

# index is the index file.
doc(
    name = "index",
    src = "index.md",
    layout = "base",
    permalink = "/",
)

# docs is the dynamic content of the site.
docs(
    name = "docs",
    deps = [
        ":index",
        "//:code_of_conduct",
        "//:contributing",
        "//:governance",
        "//:security",
        "//g3doc:community",
        "//g3doc:index",
        "//g3doc:roadmap",
        "//g3doc:style",
        "//g3doc/architecture_guide:performance",
        "//g3doc/architecture_guide:platforms",
        "//g3doc/architecture_guide:resources",
        "//g3doc/architecture_guide:security",
        "//g3doc/user_guide:FAQ",
        "//g3doc/user_guide:checkpoint_restore",
        "//g3doc/user_guide:compatibility",
        "//g3doc/user_guide:debugging",
        "//g3doc/user_guide:filesystem",
        "//g3doc/user_guide:install",
        "//g3doc/user_guide:networking",
        "//g3doc/user_guide:platforms",
        "//g3doc/user_guide/containerd:configuration",
        "//g3doc/user_guide/containerd:containerd_11",
        "//g3doc/user_guide/containerd:quick_start",
        "//g3doc/user_guide/quick_start:docker",
        "//g3doc/user_guide/quick_start:kubernetes",
        "//g3doc/user_guide/quick_start:oci",
        "//g3doc/user_guide/tutorials:cni",
        "//g3doc/user_guide/tutorials:docker",
        "//g3doc/user_guide/tutorials:docker_compose",
        "//g3doc/user_guide/tutorials:kubernetes",
    ],
)

# Generate JSON for system call tables
genrule(
    name = "syscalljson",
    outs = ["syscalls.json"],
    cmd = "$(location //runsc) -- help syscalls -format json -filename $@",
    tools = ["//runsc"],
)

# Generate markdown from the json dump.
genrule(
    name = "syscallmd",
    srcs = [":syscalljson"],
    outs = ["syscallsmd"],
    cmd = "T=$$(mktemp -d) && " +
          "$(location //website/cmd/syscalldocs) -in $< -out $$T && " +
          "tar -C $$T -czf $@ . && " +
          "rm -rf $$T",
    tools = ["//website/cmd/syscalldocs"],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
)
