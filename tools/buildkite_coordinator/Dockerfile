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

# Container image for the Buildkite coordinator.
#
# The binary must have already been built as follows:
#
#   make build TARGETS=//tools/buildkite_coordinator:buildkite_coordinator
#   cp bazel-bin/tools/buildkite_coordinator/buildkite_coordinator_/buildkite_coordinator \
#      tools/buildkite_coordinator/
#   docker build -t <image> tools/buildkite_coordinator/
FROM gcr.io/distroless/static-debian12:nonroot

COPY buildkite_coordinator /buildkite_coordinator

EXPOSE 8080

ENTRYPOINT ["/buildkite_coordinator"]
