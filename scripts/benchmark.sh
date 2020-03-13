#!/bin/bash

# Copyright 2020 The gVisor Authors.
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

source $(dirname $0)/common.sh

# Exporting for subprocesses as GCP APIs and tools check this environmental
# variable for authentication.
export GOOGLE_APPLICATION_CREDENTIALS="${KOKORO_KEYSTORE_DIR}/${GCLOUD_CREDENTIALS}"

gcloud auth activate-service-account \
   --key-file "${GOOGLE_APPLICATION_CREDENTIALS}"

gcloud config set project ${PROJECT}
gcloud config set compute/zone ${ZONE}

bazel run //benchmarks:benchmarks -- \
  --verbose \
  run-gcp \
  startup \
  --runtime=runc \
  --runtime=runsc \
  --installers=head
