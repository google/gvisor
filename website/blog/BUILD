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

doc(
    name = "containing_a_real_vulnerability",
    src = "2020-09-18-containing-a-real-vulnerability.md",
    authors = [
        "fvoznika",
    ],
    layout = "post",
    permalink = "/blog/2020/09/18/containing-a-real-vulnerability/",
)

doc(
    name = "platform_portability",
    src = "2020-10-22-platform-portability.md",
    authors = [
        "ianlewis",
        "mpratt",
    ],
    layout = "post",
    permalink = "/blog/2020/10/22/platform-portability/",
)

doc(
    name = "gvisor-rack",
    src = "2021-08-31-gvisor-rack.md",
    authors = [
        "nybidari",
    ],
    layout = "post",
    permalink = "/blog/2021/08/31/gvisor-rack/",
)

doc(
    name = "tune_gvisor_for_production_adoption",
    src = "2021-11-11-running-gvisor-in-production-at-scale-in-ant.md",
    authors = [
        "jianfengt",
        "yonghe",
    ],
    layout = "post",
    permalink = "/blog/2021/11/11/running-gvisor-in-production-at-scale-in-ant/",
)

docs(
    name = "posts",
    deps = [
        ":" + rule
        for rule in existing_rules()
    ],
)
