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

source $(dirname $0)/common.sh

# common.sh sets '-x', but it's annoying to see so much output.
set +x

# Defaults
declare -i REFRESH=0
declare NAME=$(find_branch_name)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --refresh)
      REFRESH=1
      ;;
    --help)
      echo "Use this script to build and install runsc with Docker."
      echo
      echo "usage: $0 [--refresh] [runtime_name]"
      exit 1
      ;;
    *)
      NAME=$1
      ;;
  esac
  shift
done

set_runtime "${NAME}"
echo
echo "Using runtime=${RUNTIME}"
echo

echo Building runsc...
# Build first and fail on error. $() prevents "set -e" from reporting errors.
build //runsc
declare OUTPUT="$(build //runsc)"

if [[ ${REFRESH} -eq 0 ]]; then
  install_runsc "${RUNTIME}"   --net-raw
  install_runsc "${RUNTIME}-d" --net-raw --debug --strace --log-packets

  echo
  echo "Runtimes ${RUNTIME} and ${RUNTIME}-d (debug enabled) setup."
  echo "Use --runtime="${RUNTIME}" with your Docker command."
  echo "  docker run --rm --runtime="${RUNTIME}" hello-world"
  echo
  echo "If you rebuild, use $0 --refresh."

else
  mkdir -p "$(dirname ${RUNSC_BIN})"
  cp -f ${OUTPUT} "${RUNSC_BIN}"

  echo
  echo "Runtime ${RUNTIME} refreshed."
fi

echo "Logs are in: ${RUNSC_LOGS_DIR}"
