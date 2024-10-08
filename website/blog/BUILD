load("//website:defs.bzl", "doc", "docs")

package(
    default_applicable_licenses = ["//:license"],
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
    src = "2021-12-02-running-gvisor-in-production-at-scale-in-ant.md",
    authors = [
        "jianfengt",
        "yonghe",
    ],
    layout = "post",
    permalink = "/blog/2021/12/02/running-gvisor-in-production-at-scale-in-ant/",
)

doc(
    name = "threat_detection",
    src = "2022-08-31-threat-detection.md",
    authors = [
        "fvoznika",
    ],
    layout = "post",
    permalink = "/blog/2022/08/01/threat-detection/",
)

doc(
    name = "buffer_pooling",
    src = "2022-10-24-buffer-pooling.md",
    authors = [
        "lucasmanning",
    ],
    layout = "post",
    permalink = "/blog/2022/10/24/buffer-pooling/",
)

doc(
    name = "systrap_release",
    src = "2023-04-28-systrap-release.md",
    authors = [
        "bogomolov",
    ],
    layout = "post",
    permalink = "/blog/2023/04/28/systrap-release/",
)

doc(
    name = "rootfs_overlay",
    src = "2023-05-08-rootfs-overlay.md",
    authors = [
        "ayushranjan",
    ],
    layout = "post",
    permalink = "/blog/2023/05/08/rootfs-overlay/",
)

doc(
    name = "gpu_pytorch_stable_diffusion",
    src = "2023-06-20-gpu-pytorch-stable-diffusion.md",
    authors = [
        "eperot",
    ],
    layout = "post",
    permalink = "/blog/2023/06/20/gpu-pytorch-stable-diffusion/",
)

doc(
    name = "directfs",
    src = "2023-06-27-directfs.md",
    authors = [
        "ayushranjan",
    ],
    layout = "post",
    permalink = "/blog/2023/06/27/directfs/",
)

doc(
    name = "seccomp",
    src = "2024-02-01-seccomp.md",
    authors = [
        "eperot",
    ],
    layout = "post",
    permalink = "/blog/2024/02/01/seccomp/",
)

doc(
    name = "dangerzone",
    src = "2024-09-23-dangerzone.md",
    authors = [
        "almet",
        "apyrgio",
        "eperot",
    ],
    layout = "post",
    permalink = "/blog/2024/09/23/safe-ride-into-the-dangerzone/",
)

docs(
    name = "posts",
    deps = [
        ":" + rule
        for rule in existing_rules()
    ],
)
