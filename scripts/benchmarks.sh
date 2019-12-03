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
#!/usr/bin/env bash

if [ "$#" -lt "1" ]; then
  echo "usage: $0 <--mock |--env=<filename>> ..."
  echo "example: $0 --mock --runs=8"
  exit 1
fi

source $(dirname $0)/common.sh

readonly TIMESTAMP=`date "+%Y%m%d-%H%M%S"`
readonly OUTDIR="$(mktemp --tmpdir -d run-${TIMESTAMP}-XXX)"
readonly DEFAULT_RUNTIMES="--runtime=runc --runtime=runsc --runtime=runsc-kvm"
readonly ALL_RUNTIMES="--runtime=runc --runtime=runsc --runtime=runsc-kvm"

run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} 'fio.(read|write)' --metric=bandwidth --size=5g --ioengine=sync --blocksize=1m > "${OUTDIR}/fio.csv"
run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} fio.rand --metric=bandwidth --size=5g --ioengine=sync --blocksize=4k --time=30 > "${OUTDIR}/tmp_fio.csv"
cat "${OUTDIR}/tmp_fio.csv" | grep "\(runc\|runsc\)" >> "${OUTDIR}/fio.csv" && rm "${OUTDIR}/tmp_fio.csv"

run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} 'fio.(read|write)' --metric=bandwidth --tmpfs=True --size=5g --ioengine=sync --blocksize=1m > "${OUTDIR}/fio-tmpfs.csv"
run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} fio.rand --metric=bandwidth --tmpfs=True --size=5g --ioengine=sync --blocksize=4k --time=30 > "${OUTDIR}/tmp_fio.csv"
cat "${OUTDIR}/tmp_fio.csv" | grep "\(runc\|runsc\)" >> "${OUTDIR}/fio-tmpfs.csv" && rm "${OUTDIR}/tmp_fio.csv"

run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} startup --count=50  >  "${OUTDIR}/startup.csv"
run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} density > "${OUTDIR}/density.csv"

run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} sysbench.cpu --threads=1 --max_prime=50000 --options='--max-time=5' > "${OUTDIR}/sysbench-cpu.csv"
run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} sysbench.memory --threads=1 --options='--memory-block-size=1M --memory-total-size=500G'  > "${OUTDIR}/sysbench-memory.csv"
run //benchmarks:perf -- run "$@" ${ALL_RUNTIMES} syscall > "${OUTDIR}/syscall.csv"
run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} 'network.(upload|download)' --runs=20 > "${OUTDIR}/iperf.csv"
run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} ml.tensorflow > "${OUTDIR}/tensorflow.csv"
run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} media.ffmpeg > "${OUTDIR}/ffmpeg.csv"
run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} http.httpd --path=latin100k.txt --connections=1 --connections=5 --connections=10 --connections=25 > "${OUTDIR}/httpd100k.csv"
run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} http.httpd --path=latin10240k.txt --connections=1 --connections=5 --connections=10 --connections=25 > "${OUTDIR}/httpd10240k.csv"
run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} redis > "${OUTDIR}/redis.csv"
run //benchmarks:perf -- run "$@" ${DEFAULT_RUNTIMES} 'http.(ruby|node)' > "${OUTDIR}/applications.csv"

echo "${OUTPUT}" && exit 0
