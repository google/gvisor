# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Native tools for the repository lint checks."""

load("@platforms//host:constraints.bzl", "HOST_CONSTRAINTS")
load("@rules_python//python:py_executable_info.bzl", "PyExecutableInfo")
load("@rules_python//python:py_runtime_info.bzl", "PyRuntimeInfo")

_BUILDIFIER = "@buildifier_prebuilt//buildifier:toolchain"
_SPAWN = "@bazel_lib//lib:spawn_binary_toolchain_type"

def _buildifier_check(ctx):
    tools = ctx.exec_groups["lint"].toolchains
    buildifier = tools[_BUILDIFIER].tool
    report = ctx.actions.declare_file(ctx.label.name + ".report")
    args = ctx.actions.args()
    args.add("--stdout", report)
    args.add("--")
    args.add(buildifier)
    args.add_all(ctx.attr.flags)
    args.add("--config=" + (ctx.file.config.path if ctx.file.config else "off"))
    args.add_all(["--mode=check", "--lint=warn", "--"])
    args.add_all(ctx.files.srcs)
    ctx.actions.run(
        executable = tools[_SPAWN].spawn_binary_info.bin,
        arguments = [args],
        inputs = ctx.files.srcs + ctx.files.config,
        tools = [buildifier],
        outputs = [report],
        exec_group = "lint",
        mnemonic = "BuildifierCheck",
        progress_message = "Checking Starlark formatting (fix with 'bazel run //tools/lint:format' or 'make lint-fix')",
    )
    return [DefaultInfo(files = depset([report]))]

buildifier_check = rule(
    implementation = _buildifier_check,
    attrs = {
        "config": attr.label(allow_single_file = True),
        "flags": attr.string_list(),
        "srcs": attr.label_list(allow_files = True),
    },
    exec_groups = {"lint": exec_group(toolchains = [_BUILDIFIER, _SPAWN])},
)

def _buildifier_format(ctx):
    tool = ctx.exec_groups["client"].toolchains[_BUILDIFIER].tool
    command = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(output = command, target_file = tool, is_executable = True)
    return [DefaultInfo(executable = command, runfiles = ctx.runfiles(files = [tool]))]

buildifier_format = rule(
    implementation = _buildifier_format,
    executable = True,
    # bazel run executes the formatter on the client, including when the
    # workspace builds its targets on a different operating system or CPU.
    exec_groups = {"client": exec_group(toolchains = [_BUILDIFIER], exec_compatible_with = HOST_CONSTRAINTS)},
)

def _python_inputs(ctx):
    tool = ctx.attr.tool
    runtime = tool[PyRuntimeInfo]
    if not runtime.interpreter:
        fail("source lint requires a declared Python interpreter")
    return [OutputGroupInfo(
        interpreter = depset([runtime.interpreter]),
        main = depset([tool[PyExecutableInfo].main]),
        runtime = runtime.files,
    )]

python_inputs = rule(
    implementation = _python_inputs,
    attrs = {"tool": attr.label(mandatory = True, providers = [PyExecutableInfo, PyRuntimeInfo])},
)
