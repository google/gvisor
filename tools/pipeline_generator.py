# Copyright 2018 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generates a pipeline for buildkite."""

import os
import sys
import yaml

pipeline_file = ".buildkite/pipeline_static.yaml"
label = os.environ.get("BUILDKITE_LABEL")
cmd = os.environ.get("CMD")
runtime_args = os.environ.get("RUNTIME_ARGS")

pipeline = None
try:
  with open(pipeline_file, "r") as f:
    pipeline = yaml.safe_load(f)
except FileNotFoundError:
  sys.exit(f"Error: {pipeline_file} not found")

found_step = None
for step in pipeline.get("steps", []):
  if step.get("label") == label:
    found_step = step
    break

if not found_step:
  sys.exit(f'Error: Step with label "{label}" not found in {pipeline_file}')

step = found_step.copy()
# step["label"] = f"{label} (Parallel)"
# step["parallelism"] = total_partitions
# step["command"] = f"make {cmd}-runtime-tests PARTITION=
# $((BUILDKITE_PARALLEL_JOB + 1)) TOTAL_PARTITIONS=
# $BUILDKITE_PARALLEL_JOB_COUNT RUNTIME_ARGS=\"{runtime_args}\""

# if "env" not in step:
#     step["env"] = {}

# step["env"]["BUILDKITE_PIPELINE_INSTALL_RUNTIME"] = "true"

print(yaml.dump([step], sort_keys=False))
