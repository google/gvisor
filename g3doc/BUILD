load("//website:defs.bzl", "doc")

package(
    default_visibility = ["//website:__pkg__"],
    licenses = ["notice"],
)

doc(
    name = "index",
    src = "README.md",
    category = "Project",
    data = glob([
        "*.png",
        "*.svg",
    ]),
    permalink = "/docs/",
    weight = "0",
)

doc(
    name = "roadmap",
    src = "roadmap.md",
    category = "Project",
    permalink = "/roadmap/",
    weight = "10",
)

doc(
    name = "community",
    src = "community.md",
    category = "Project",
    permalink = "/community/",
    subcategory = "Community",
    weight = "10",
)

doc(
    name = "style",
    src = "style.md",
    category = "Project",
    permalink = "/community/style_guide/",
    subcategory = "Community",
    weight = "99",
)
