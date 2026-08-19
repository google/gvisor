load("//tools/yamltest:defs.bzl", "yaml_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

exports_files([
    "reviewer.json",
])

yaml_test(
    name = "github_workflows_test",
    srcs = glob(["workflows/*.yml"]),
    schema = "@github_workflow_schema//file",
)
