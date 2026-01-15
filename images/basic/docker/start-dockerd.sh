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

set -xe -o pipefail

USE_OVERLAY_DRIVER=true
while [[ $# -gt 0 ]]; do
  case $1 in
    --no-overlay)
      USE_OVERLAY_DRIVER=false
      shift
      ;;
    *)
      shift
      ;;
  esac
done

# When dockerd uses the overlay storage driver, it will try to mount an overlay
# filesystem under /var/lib/docker. gVisor only supports tmpfs as an upper
# layer, so we mount a tmpfs if it isn't already present.
if [[ "${USE_OVERLAY_DRIVER}" == "true" ]]; then
  current_fs=$(stat -f -c %T /var/lib/docker 2>/dev/null || echo "none")
  if [[ "${current_fs}" != "tmpfs" ]]; then
    mkdir -p /var/lib/docker
    mount -t tmpfs -o size=2G tmpfs /var/lib/docker
  else
    echo "/var/lib/docker is already tmpfs, skipping mount."
  fi
fi

EXTRA_DOCKERD_FLAGS=()
docker_version=$(dockerd --version)
# Docker 29+ does not automatically fall back to the vfs driver when it cannot
# mount an overlayfs, so we explicitly disable it when --no-overlay is passed.
if [[ ${docker_version} =~ version\ ([0-9]+) ]] && [[ ${BASH_REMATCH[1]} -ge 29 ]]; then
  if [[ "${USE_OVERLAY_DRIVER}" != "true" ]]; then
    EXTRA_DOCKERD_FLAGS+=(--feature containerd-snapshotter=false)
  fi
fi

dev=$(ip route show default | sed 's/.*\sdev\s\(\S*\)\s.*$/\1/')
addr=$(ip addr show dev "$dev"  | grep -w inet | sed 's/^\s*inet\s\(\S*\)\/.*$/\1/')

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables-legacy -t nat -A POSTROUTING -o "$dev" -j SNAT --to-source "$addr" -p tcp
iptables-legacy -t nat -A POSTROUTING -o "$dev" -j SNAT --to-source "$addr" -p udp

exec /usr/bin/dockerd --iptables=false --ip6tables=false -D "${EXTRA_DOCKERD_FLAGS[@]}"
