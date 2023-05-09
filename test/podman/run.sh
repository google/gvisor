#!/bin/bash

# Copyright 2022 The gVisor Authors.
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

set -u -x -e -o pipefail

export DEBIAN_FRONTEND=noninteractive
sudo -E apt-get install -qy podman

test_dir="$(mktemp -d /tmp/gvisor-podman.XXXXXX)"
podman_runtime="${test_dir}/runsc.podman"

cleanup() {
        rm -rf "${test_dir}"
}
trap cleanup EXIT

make copy TARGETS=runsc DESTINATION="${test_dir}"
cat > "${podman_runtime}" <<EOF
#!/bin/bash

exec $test_dir/runsc --ignore-cgroups --debug --debug-log ${test_dir}/runsc.log "\$@"
EOF
chmod ugo+x "${podman_runtime}"
chmod ugo+x "${test_dir}/runsc"
chmod ugo+xwr "${test_dir}"
grep podman-testuser /etc/passwd || \
adduser   --disabled-login  --disabled-password podman-testuser < /dev/null
(
        cd /
        sudo -u podman-testuser podman run --runtime "${podman_runtime}" alpine echo "Hello, world"
)
