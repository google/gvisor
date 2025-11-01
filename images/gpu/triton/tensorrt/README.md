# Building TensorRT engine for Llama2-7B-Chat-HF model

This guide provides instructions for building TensorRT engine files for the
Llama2-7B-Chat-HF model.

## 1. Create a Google Cloud VM with GPU

First, create a Google Cloud VM with the necessary accelerator.

Set the following environment variables for your project:

```bash
export IMAGE="common-cu128-ubuntu-2204-nvidia-570-v20251009"
export ZONE="us-central1-a"
export INSTANCE_NAME="model-prep"
export MACHINE_TYPE="g2-standard-32"
export ACCELERATOR="type=nvidia-l4,count=1"
export PROJECT="<your-project>"
```

Then, create the instance using the following command:

```bash
gcloud compute instances create $INSTANCE_NAME \
   --zone=$ZONE \
   --image=$IMAGE \
   --machine-type=$MACHINE_TYPE \
   --image-project=deeplearning-platform-release \
   --maintenance-policy=TERMINATE \
   --accelerator=$ACCELERATOR \
   --metadata="install-nvidia-driver=True" \
   --boot-disk-size=4TB \
   --boot-disk-type=pd-ssd \
   --boot-disk-device-name=boot-disk \
   --no-shielded-secure-boot \
   --project=$PROJECT
```

## 2. Install Dependencies

Connect to the newly created VM and install the required packages:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg neovim python3-dev
```

## 3. Install Docker

Install Docker on the VM:

Restart Docker and add your user to the `docker` group to run Docker commands
without `sudo`:

```bash
sudo systemctl restart docker
sudo usermod -a -G docker $USER
newgrp docker
```

## 4. Build and Run Docker Container

In your VM, create `Dockerfile.llama2-7b-chat-hf` with the content of
`images/gpu/triton/tensorrt/Dockerfile.llama-2-7b-chat-hf`. Don't forget to
provide your own HF token.

Build the Docker image:

```bash
docker build . -f Dockerfile.llama2-7b-chat-hf -t tensorrt:llama2-7b-chat-hf
```

Run the Docker container:

```bash
docker run --rm -it --net host --shm-size=25g --ulimit memlock=-1 --ulimit stack=67108864 --gpus all -p 8000:8000 tensorrt:llama2-7b-chat-hf bash
```

## 5. Convert Model and Build TensorRT Engine

Inside the container, run the following commands to generate the model
checkpoint, quantize it, and build the TensorRT engine.

Convert the checkpoint: `bash python convert_checkpoint.py --model_dir
/llama-2-7b-chat-hf \ --output_dir /tllm_checkpoint_1gpu_tp1 \ --dtype float16 \
--tp_size 1`

Quantize the model: `bash python3 ../../../quantization/quantize.py
--dtype=float16 --output_dir /tllm_checkpoint_1gpu_tp1 --model_dir
/llama-2-7b-chat-hf --qformat=fp8 --kv_cache_dtype=fp8 --tp_size 1`

Build the TensorRT engine: `bash trtllm-build --checkpoint_dir
/tllm_checkpoint_1gpu_tp1 \ --output_dir /engines/llama-2-7b-chat-hf/fp8/1-gpu/
\ --gemm_plugin auto \ --max_batch_size 1`
