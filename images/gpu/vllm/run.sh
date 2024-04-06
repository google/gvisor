#!/bin/sh

# Copyright 2024 The gVisor Authors.
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

if ! test -x /model; then
  echo 'Must mount a model directory at /model.' >&2
  exit 1
fi
exec python -m vllm.entrypoints.api_server \
  --host=0.0.0.0                           \
  --port=7080                              \
  --tensor-parallel-size=1                 \
  --swap-space=16                          \
  --gpu-memory-utilization=0.95            \
  --max-num-batched-tokens=4096            \
  --model=/model
