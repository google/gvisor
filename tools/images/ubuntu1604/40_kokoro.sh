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

# Declare kokoro's required public keys.
declare -r ssh_public_keys=(
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDg7L/ZaEauETWrPklUTky3kvxqQfe2Ax/2CsSqhNIGNMnK/8d79CHlmY9+dE1FFQ/RzKNCaltgy7XcN/fCYiCZr5jm2ZtnLuGNOTzupMNhaYiPL419qmL+5rZXt4/dWTrsHbFRACxT8j51PcRMO5wgbL0Bg2XXimbx8kDFaurL2gqduQYqlu4lxWCaJqOL71WogcimeL63Nq/yeH5PJPWpqE4P9VUQSwAzBWFK/hLeds/AiP3MgVS65qHBnhq0JsHy8JQsqjZbG7Iidt/Ll0+gqzEbi62gDIcczG4KC0iOVzDDP/1BxDtt1lKeA23ll769Fcm3rJyoBMYxjvdw1TDx sabujp@trigger.mtv.corp.google.com"
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNgGK/hCdjmulHfRE3hp4rZs38NCR8yAh0eDsztxqGcuXnuSnL7jOlRrbcQpremJ84omD4eKrIpwJUs+YokMdv4= sabujp@trigger.svl.corp.google.com"
)

# Install dependencies.
apt-get update && apt-get install -y rsync coreutils python-psutil qemu-kvm python-pip python3-pip zip

# junitparser is used to merge junit xml files.
pip install junitparser

# We need a kbuilder user.
if useradd -c "kbuilder user" -m -s /bin/bash kbuilder; then
    # User was added successfully; we add the relevant SSH keys here.
    mkdir -p ~kbuilder/.ssh
    (IFS=$'\n'; echo "${ssh_public_keys[*]}") > ~kbuilder/.ssh/authorized_keys
    chmod 0600 ~kbuilder/.ssh/authorized_keys
    chown -R kbuilder ~kbuilder/.ssh
fi

# Give passwordless sudo access.
cat > /etc/sudoers.d/kokoro <<EOF
kbuilder ALL=(ALL) NOPASSWD:ALL
EOF

# Ensure we can run Docker without sudo.
usermod -aG docker kbuilder

# Ensure that we can access kvm.
usermod -aG kvm kbuilder

# Ensure that /tmpfs exists and is writable by kokoro.
#
# Note that kokoro will typically attach a second disk (sdb) to the instance
# that is used for the /tmpfs volume. In the future we could setup an init
# script that formats and mounts this here; however, we don't expect our build
# artifacts to be that large.
mkdir -p /tmpfs && chmod 0777 /tmpfs && touch /tmpfs/READY
