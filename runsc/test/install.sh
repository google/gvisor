#!/bin/bash

# Copyright 2018 Google Inc.
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

# Fail on any error
set -e

# Defaults
declare runtime=runsc-test
declare uninstall=0

function findExe() {
  local exe=${1}

  local path=$(find bazel-bin/runsc -type f -executable -name "${exe}" | head -n1)
  if [[ "${path}" == "" ]]; then
    echo "Location of ${exe} not found in bazel-bin" >&2
    exit 1
  fi
  echo "${path}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime)
      shift
      [ "$#" -le 0 ] && echo "No runtime provided" && exit 1
      runtime=$1
      ;;
    -u)
      uninstall=1
      ;;
    *)
      echo "Unknown option: ${1}"
      echo ""
      echo "Usage: ${0} [--runtime <name>] [-u]"
      echo "  --runtime    sets the runtime name, default: runsc-test"
      echo "  -u           uninstall the runtime"
      exit 1
  esac
  shift
done

# Find location of executables.
declare -r dockercfg=$(findExe dockercfg)
[[ "${dockercfg}" == "" ]] && exit 1

declare runsc=$(findExe runsc)
[[ "${runsc}" == "" ]] && exit 1

if [[ ${uninstall} == 0 ]]; then
  rm -rf /tmp/${runtime}
  mkdir -p /tmp/${runtime}
  cp "${runsc}" /tmp/${runtime}/runsc
  runsc=/tmp/${runtime}/runsc

  # Make tmp dir and runsc binary readable and executable to all users, since it
  # will run in an empty user namespace.
  chmod a+rx "${runsc}" $(dirname "${runsc}")

  # Make log dir executable and writable to all users for the same reason.
  declare logdir=/tmp/"${runtime?}/logs"
  mkdir -p "${logdir}"
  sudo -n chmod a+wx "${logdir}"

  declare -r args="--debug-log '${logdir}/' --debug --strace --log-packets"
  sudo -n "${dockercfg}" runtime-add "${runtime}" "${runsc}" ${args}
  sudo -n "${dockercfg}" runtime-add "${runtime}"-kvm "${runsc}" --platform=kvm ${args}
  sudo -n "${dockercfg}" runtime-add "${runtime}"-hostnet "${runsc}" --network=host ${args}
  sudo -n "${dockercfg}" runtime-add "${runtime}"-overlay "${runsc}" --overlay ${args}

else
  sudo -n "${dockercfg}" runtime-rm "${runtime}"
  sudo -n "${dockercfg}" runtime-rm "${runtime}"-kvm
  sudo -n "${dockercfg}" runtime-rm "${runtime}"-hostnet
  sudo -n "${dockercfg}" runtime-rm "${runtime}"-overlay
fi

echo "Restarting docker service..."
sudo -n /etc/init.d/docker restart
