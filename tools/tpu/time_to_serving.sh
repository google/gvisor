#!/bin/bash

# Copyright 2023 The gVisor Authors.
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

# Script to benchmark the time from startup to serving a model in vLLM.
# Usage: time_to_serving.sh <model> <hf_username> <hf_token>
# Example: time_to_serving.sh Qwen/Qwen2.5-1.5B-Instruct gvisor-eng hf_xxxxxx 
set -ueo pipefail

MODEL=${1-"Qwen/Qwen2.5-1.5B-Instruct"}
HF_USERNAME=${2-""}
HF_TOKEN=${3-""}
NUM_TPUS=$(($(ls /dev/vfio | wc -l) - 1))
DOCKERFILE="../images/tpu/vllm/serve/Dockerfile.x86_64"

if [[ $NUM_TPUS -eq 0 ]]; then
  echo "No TPUs found."
  exit 1
fi

docker build -f $DOCKERFILE \
 --build-arg HF_USERNAME="$HF_USERNAME" --build-arg HF_TOKEN="$HF_TOKEN" . \
 -t vllm-serve --build-arg MODEL="$MODEL"
CONTAINER_ID=$(docker create --privileged --net host --shm-size=16G --rm -it vllm-serve \
 python3 -m vllm.entrypoints.openai.api_server --model /model \
 --chat-template /vllm/examples/template_chatml.jinja --tensor-parallel-size=$NUM_TPUS \
 --max-model-len=512 --enforce-eager)

trap "docker stop $CONTAINER_ID > /dev/null" EXIT

docker start "$CONTAINER_ID" > /dev/null
echo "Container $CONTAINER_ID started..."
ready=false
start_time=$(date +%s)
while ! $ready; do
  sleep 0.3
  docker logs "$CONTAINER_ID" | grep "Uvicorn running on" && ready=true
  docker logs "$CONTAINER_ID" | grep "No such container" && exit 1
done
end_time=$(date +%s)

echo "Time to start: $((end_time - start_time)) seconds"
