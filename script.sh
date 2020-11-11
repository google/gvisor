#!/bin/bash -x
# A simple script running a single benchmark against all runtime configurations.

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

export TARGETS="test/benchmarks/base:size_test"
export ARGS="--test.bench=. --test.v --test.benchtime=1x"
export BENCHMARKS_SUITE="size"
export BENCHMARKS_PROJECT="linux-testing-zkoopmans"
export BENCHMARKS_DATASET="testdata"
export BENCHMARKS_TABLE="bqtest"
export BENCHMARKS_UPLOAD="true"
export BENCHMARKS_PLATFORMS="ptrace"

wget https://github.com/bazelbuild/bazel/releases/download/3.7.0/bazel-3.7.0-installer-linux-x86_64.sh
chmod +x bazel-3.7.0-installer-linux-x86_64.sh
sudo ./bazel-3.7.0-installer-linux-x86_64.sh

docker --version
bazel --version

make load-benchmarks-images
file=$(mktemp -t tmp.runc.XXXXXX)
echo "${file}"

IFS=' ' read -r -a array <<< "${ARGS}"

bazel run "${TARGETS}" -- --runtime=runc "${array[@]}" | tee "${file}" || true


bazel run tools/parsers:parser -- parse --file="${file}" --debug
