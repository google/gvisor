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

# Add dependencies.
while true; do
  if (apt-get update && apt-get install -y \
      apt-transport-https \
      ca-certificates \
      curl \
      gnupg-agent \
      software-properties-common); then
    break
  fi
  result=$?
  if [[ $result -ne 100 ]]; then
    exit $result
  fi
done

# Install the key.
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -

# Add the repository.
add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"

# Install docker.
while true; do
  if (apt-get update && apt-get install -y \
      docker-ce \
      docker-ce-cli \
      containerd.io); then
    break
  fi
  result=$?
  if [[ $result -ne 100 ]]; then
    exit $result
  fi
done

# Enable experimental features, for cross-building aarch64 images.
cat > /etc/docker/daemon.json <<EOF
{
    "experimental": true
}
EOF
