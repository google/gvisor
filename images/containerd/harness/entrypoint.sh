#!/usr/bin/env bash
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

set -euo pipefail

if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
    mkdir -p /sys/fs/cgroup/init
    while read -r pid; do
        echo "${pid}" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
    done < /sys/fs/cgroup/cgroup.procs
    for c in $(cat /sys/fs/cgroup/cgroup.controllers); do
        echo "+${c}" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
        echo "+${c}" > /sys/fs/cgroup/init/cgroup.subtree_control 2>/dev/null || true
    done
fi

if command -v update-alternatives >/dev/null 2>&1; then
    update-alternatives --set iptables /usr/sbin/iptables-legacy >/dev/null 2>&1 || true
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy >/dev/null 2>&1 || true
fi

touch /etc/crictl.yaml 2>/dev/null || true

: "${CONTAINERD_VERSION:?CONTAINERD_VERSION must be set}"
version_dir="/opt/containerd/${CONTAINERD_VERSION}/bin"
if [[ ! -x "${version_dir}/containerd" ]]; then
    echo "containerd ${CONTAINERD_VERSION} is not baked into this image; have:" >&2
    ls /opt/containerd >&2
    exit 1
fi
for bin in "${version_dir}"/*; do
    ln -sf "${bin}" "/usr/local/bin/$(basename "${bin}")"
done

exec "$@"
