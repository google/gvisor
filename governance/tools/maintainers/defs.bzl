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

"""Generate the governance artifacts from their declared inputs."""

def governance_files(name):
    """Generate CODEOWNERS and MAINTAINERS.md under name."""
    for format in ["CODEOWNERS", "MAINTAINERS.md"]:
        native.genrule(
            name = name + "_" + format,
            srcs = [
                "@governance_areas//:areas.yaml",
                "maintainers.yaml",
            ],
            outs = [name + "/" + format],
            cmd = "$(execpath //governance/tools/maintainers:maintainers_gen) " +
                  "-input $(location maintainers.yaml) " +
                  "-areas $(location @governance_areas//:areas.yaml) " +
                  "-format " + format + " -output $@",
            tools = ["//governance/tools/maintainers:maintainers_gen"],
            visibility = ["//:__pkg__"],
        )
