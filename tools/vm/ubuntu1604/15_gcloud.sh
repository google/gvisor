#!/bin/bash

# Copyright 2019 The gVisor Authors.
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

set -xeo pipefail

# Install all essential build tools.
while true; do
  if (apt-get update && apt-get install -y \
      apt-transport-https \
      ca-certificates \
      gnupg); then
    break
  fi
  result=$?
  if [[ $result -ne 100 ]]; then
    exit $result
  fi
done

# Add gcloud repositories.
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | \
  tee -a /etc/apt/sources.list.d/google-cloud-sdk.list

# Add the appropriate key.
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | \
  apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -

# Install the gcloud SDK.
while true; do
  if (apt-get update && apt-get install -y google-cloud-sdk); then
    break
  fi
  result=$?
  if [[ $result -ne 100 ]]; then
    exit $result
  fi
done
