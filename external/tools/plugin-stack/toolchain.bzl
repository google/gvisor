# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Additional selected C toolchain variables needed by the plugin's Make build."""

load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")

def _plugin_toolchain_impl(ctx):
    toolchain = find_cc_toolchain(ctx)
    if toolchain.compiler not in ["gcc", "clang"]:
        fail("The plugin requires a GCC or Clang toolchain, got {}".format(toolchain.compiler))

    # rules_foreign_cc supplies CC, AR and LD, but not objdump. The Makefile
    # resolves a relative path against foreign_cc's execution root before
    # recursive builds change directories.
    return [
        platform_common.TemplateVariableInfo({"PLUGIN_OBJDUMP": toolchain.objdump_executable}),
        DefaultInfo(
            files = toolchain.all_files,
            runfiles = ctx.runfiles(transitive_files = toolchain.all_files),
        ),
    ]

plugin_toolchain = rule(
    implementation = _plugin_toolchain_impl,
    fragments = ["cpp"],
    toolchains = use_cc_toolchain(),
)
