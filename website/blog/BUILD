load("//website:defs.bzl", "doc", "docs")

package(
    default_visibility = ["//website:__pkg__"],
    licenses = ["notice"],
)

exports_files(["index.html"])

doc(
    name = "security_basics",
    src = "2019-11-18-security-basics.md",
    authors = [
        "jsprad",
        "zkoopmans",
    ],
    layout = "post",
    permalink = "/blog/2019/11/18/gvisor-security-basics-part-1/",
)

doc(
    name = "networking_security",
    src = "2020-04-02-networking-security.md",
    authors = [
        "igudger",
    ],
    layout = "post",
    permalink = "/blog/2020/04/02/gvisor-networking-security/",
)

docs(
    name = "posts",
    deps = [
        ":" + rule
        for rule in existing_rules()
    ],
)
