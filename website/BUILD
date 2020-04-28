load("//tools:defs.bzl", "go_binary", "pkg_tar")
load("//website:defs.bzl", "docs")

package(licenses = ["notice"])

# website is the full container image. Note that this actually just collects
# other dependendcies and runs Docker locally to import and tag the image.
sh_binary(
    name = "website",
    srcs = ["import.sh"],
    data = [":files"],
    tags = [
        "local",
        "manual",
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
        ":docs",
        ":posts",
        ":static",
        ":syscallmd",
        "//website/cmd/server",
    ],
    outs = ["files.tgz"],
    cmd = "set -x; " +
          "rm -rf $(@D)/input  && mkdir -p $(@D)/input && " +
          "rm -rf $(@D)/output && mkdir -p $(@D)/output/_site && " +
          "tar -xf $(location :config)    -C $(@D)/input && " +
          "tar -xf $(location :docs)      -C $(@D)/input && " +
          "tar -xf $(location :posts)     -C $(@D)/input && " +
          "tar -xf $(location :syscallmd) -C $(@D)/input && " +
          "find $(@D)/input -type f -exec chmod u+rw {} \\; && " +
          "docker run -i --user $$(id -u):$$(id -g) " +
          "-v $$(readlink -m $(@D)/input):/input " +
          "-v $$(readlink -m $(@D)/output/_site):/output " +
          "gvisor.dev/images/jekyll && " +
          "tar -xf $(location :static) -C $(@D)/output/_site && " +
          "docker run -i --user $$(id -u):$$(id -g) " +
          "-v $$(readlink -m $(@D)/output/_site):/output " +
          "gvisor.dev/images/jekyll " +
          "/usr/gem/bin/htmlproofer " +
          "--disable-external " +
          "--check-html " +
          "/output && " +
          "cp $(location //website/cmd/server) $(@D)/output/server && " +
          "tar -zcf $@ -C $(@D)/output . && " +
          "rm -rf $(@D)/input $(@D)/output",
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
    srcs = glob([
        "archive.key",
        "performance/**",
    ]),
    strip_prefix = "./",
)

# config is "mostly" static content. These are parts of the site that are
# present when jekyll runs, but are not dynamically generated.
pkg_tar(
    name = "config",
    srcs = glob([
        "assets/**",
        "blog/*.html",
        "*.yml",
        "css/**",
        "index.md",
        "_includes/**",
        "_layouts/**",
        "_plugins/**",
        "_sass/**",
    ]),
    strip_prefix = "./",
)

# docs is the dynamic content of the site.
docs(
    name = "docs",
    deps = [
        "//:code_of_conduct",
        "//:contributing",
        "//:governance",
        "//:security",
        "//g3doc:community",
        "//g3doc:index",
        "//g3doc:roadmap",
        "//g3doc/architecture_guide:index",
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
        "//g3doc/user_guide/quick_start:docker",
        "//g3doc/user_guide/quick_start:kubernetes",
        "//g3doc/user_guide/quick_start:oci",
        "//g3doc/user_guide/tutorials:cni",
        "//g3doc/user_guide/tutorials:docker",
        "//g3doc/user_guide/tutorials:kubernetes",
    ],
)

# posts are moved to the _posts directory.
pkg_tar(
    name = "posts",
    srcs = glob([
        "blog/*.md",
    ]),
    package_dir = "_posts",
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
    cmd = "mkdir $(@D)/_tmp && \
           $(location //website/cmd/generate-syscall-docs) -in $< -out $(@D)/_tmp && \
           tar -C $(@D)/_tmp -czf $@ . && \
           rm -rf $(@D)/_tmp",
    tools = ["//website/cmd/generate-syscall-docs"],
)
