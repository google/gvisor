#!/bin/bash

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

# Script to easily run gpu tests on all supported driver versions. This should
# be run from the gVisor repo root directory.
set -ueo pipefail

json_file=$(mktemp /tmp/cos_gpu_compatibility_test.XXXXXX)
trap "rm -f ${json_file}" EXIT

gcloud compute images list --project cos-cloud \
  --filter="family:cos*"  --format json > "${json_file}"

make run TARGETS=test/gpu:cos_gpu_compatibility_test ARGS="-test.v --image_json=${json_file}"
