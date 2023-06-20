# Running Stable Diffusion on GPU with gVisor

gVisor is [starting to support GPU][gVisor GPU support] workloads. This post
showcases running the [Stable Diffusion] generative model from [Stability AI] to
generate images using a GPU from within gVisor. Both the
[Automatic1111 Stable Diffusion web UI][automatic1111/stable-diffusion-webui]
and the [PyTorch] code used by Stable Diffusion were run entirely within gVisor
while being able to leverage the NVIDIA GPU.

![A sandboxed GPU](/assets/images/2023-06-20-sandboxed-gpu.png "A sandboxed GPU.")
<span class="attribution">**Sand**boxing a GPU. Generated with Stable Diffusion
v1.5.<br/>This picture gets a lot deeper once you realize that GPUs are made out
of sand.</span>

--------------------------------------------------------------------------------

## Disclaimer

As of this writing (2023-06), [gVisor's GPU support][gVisor GPU support] is not
generalized. Only some PyTorch workloads have been tested on NVIDIA T4, L4,
A100, and H100 GPUs, using the specific driver versions `525.60.13` and
`525.105.17`. Contributions are welcome to expand this set to support other GPUs
and driver versions!

Additionally, while gVisor does its best to sandbox the workload, interacting
with the GPU inherently requires running code on GPU hardware, where isolation
is enforced by the GPU driver and hardware itself rather than gVisor. More to
come soon on the value of the protection gVisor provides for GPU workloads.

In a few months, gVisor's GPU support will have broadened and become
easier-to-use, such that it will not be constrained to the specific sets of
versions used here. In the meantime, this blog stands as an example of what's
possible today with gVisor's GPU support.

![Various space suit helmets](/assets/images/2023-06-20-spacesuit-helmets.png "Various space suit helmets."){:width="100%"}
<span class="attribution">**A collection of astronaut helmets in various styles**.<br/>Other than the helmet in the center, each helmet was generated using Stable Diffusion v1.5.</span>

## Why even do this?

The recent explosion of machine learning models has led to a large number of new
open-source projects. Much like it is good practice to be careful about running
new software downloaded from the Internet, it is good practice to run new
open-source projects in a sandbox. For projects like the
[Automatic1111 Stable Diffusion web UI][automatic1111/stable-diffusion-webui],
which automatically download various models, components, and
[extensions][Stable Diffusion Web UI extensions] from external repositories as
the user enables them in the web UI, this principle applies all the more.

Additionally, within the machine learning space, tooling for packaging and
distributing models are still nascent. While some models (including Stable
Diffusion) are packaged using the more secure [safetensors] format, **the
majority of models available online today are distributed using the
[Pickle format], which can execute arbitrary Python code** upon deserialization.
As such, even when using trustworthy software, using Pickle-formatted models may
still be risky. gVisor provides a layer of protection around this process which
helps protect the host machine.

Third, **machine learning applications are typically not I/O heavy**, which
means they tend not to experience a significant performance overhead. The
process of uploading code to the GPU is not a significant number of system
calls, and most communication to/from the GPU happens over shared memory, where
gVisor imposes no overhead. Therefore, the question is not so much "why should I
run this GPU workload in gVisor?" but rather "why not?".

![Cool astronauts don't look at explosions](/assets/images/2023-06-20-turbo.png "Cool astronauts don't look at explosions.")
<span class="attribution">**Cool astronauts don't look at explosions**.
Generated using Stable Diffusion v1.5.</span>

Lastly, running GPU workloads in gVisor is pretty cool.

## Setup

We use a Debian virtual machine on GCE. The machine needs to have a GPU and to
have sufficient RAM and disk space to handle Stable Diffusion and its large
model files. The following command creates a VM with 4 vCPUs, 15GiB of RAM, 64GB
of disk space, and an NVIDIA T4 GPU, running Debian 11 (bullseye). Since this is
just an experiment, the VM is set to self-destruct after 6 hours.

```shell
$ gcloud compute instances create stable-diffusion-testing \
    --zone=us-central1-a \
    --machine-type=n1-standard-4 \
    --max-run-duration=6h \
    --instance-termination-action=DELETE \
    --maintenance-policy TERMINATE \
    --accelerator=count=1,type=nvidia-tesla-t4 \
    --create-disk=auto-delete=yes,boot=yes,device-name=stable-diffusion-testing,image=projects/debian-cloud/global/images/debian-11-bullseye-v20230509,mode=rw,size=64
$ gcloud compute ssh --zone=us-central1-a stable-diffusion-testing
```

All further commands in this post are performed while SSH'd into the VM. We
first need to install the specific NVIDIA driver version that gVisor is
currently compatible with.

```shell
$ sudo apt-get update && sudo apt-get -y upgrade
$ sudo apt-get install -y build-essential linux-headers-$(uname -r)
$ DRIVER_VERSION=525.60.13
$ curl -fSsl -O "https://us.download.nvidia.com/tesla/$DRIVER_VERSION/NVIDIA-Linux-x86_64-$DRIVER_VERSION.run"
$ sudo sh NVIDIA-Linux-x86_64-$DRIVER_VERSION.run
```

<!--
The above in a single live, for convenience:
DRIVER_VERSION=525.60.13; sudo apt-get update && sudo apt-get -y upgrade && sudo apt-get install -y build-essential linux-headers-$(uname -r) && curl -fSsl -O "https://us.download.nvidia.com/tesla/$DRIVER_VERSION/NVIDIA-Linux-x86_64-$DRIVER_VERSION.run" && sudo sh NVIDIA-Linux-x86_64-$DRIVER_VERSION.run
-->

Next, we install Docker, per [its instructions][Docker installation on Debian].

```shell
$ sudo apt-get install -y ca-certificates curl gnupg
$ sudo install -m 0755 -d /etc/apt/keyrings
$ curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor --batch --yes -o /etc/apt/keyrings/docker.gpg
$ sudo chmod a+r /etc/apt/keyrings/docker.gpg
$ echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
$ sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli
```

<!--
The above in a single live, for convenience:
sudo apt-get install -y ca-certificates curl gnupg && sudo install -m 0755 -d /etc/apt/keyrings && curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor --batch --yes -o /etc/apt/keyrings/docker.gpg && sudo chmod a+r /etc/apt/keyrings/docker.gpg && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null && sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli
-->

We will also need the [NVIDIA container toolkit], which enables use of GPUs with
Docker. Per its
[installation instructions][NVIDIA container toolkit installation]:

```shell
$ distribution=$(. /etc/os-release;echo $ID$VERSION_ID) && curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg && curl -s -L https://nvidia.github.io/libnvidia-container/$distribution/libnvidia-container.list | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
$ sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit
```

Of course, we also need to [install gVisor][gVisor setup] itself.

```shell
$ sudo apt-get install -y apt-transport-https ca-certificates curl gnupg
$ curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
$ echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
$ sudo apt-get update && sudo apt-get install -y runsc

＃ As gVisor does not yet enable GPU support by default, we need to set the flags
＃ that will enable it:
$ sudo runsc install -- --nvproxy=true --nvproxy-docker=true

$ sudo systemctl restart docker
```

Now, let's make sure everything works by running commands that involve more and
more of what we just set up.

```shell
＃ Check that the NVIDIA drivers are installed, with the right version, and with
＃ a supported GPU attached
$ sudo nvidia-smi -L
GPU 0: Tesla T4 (UUID: GPU-6a96a2af-2271-5627-34c5-91dcb4f408aa)
$ sudo cat /proc/driver/nvidia/version
NVRM version: NVIDIA UNIX x86_64 Kernel Module  525.60.13  Wed Nov 30 06:39:21 UTC 2022

＃ Check that Docker works.
$ sudo docker version
＃ [...]
Server: Docker Engine - Community
 Engine:
  Version:          24.0.2
＃ [...]

＃ Check that gVisor works.
$ sudo docker run --rm --runtime=runsc debian:latest dmesg | head -1
[    0.000000] Starting gVisor...

＃ Check that Docker GPU support (without gVisor) works.
$ sudo docker run --rm --gpus=all nvidia/cuda:11.6.2-base-ubuntu20.04 nvidia-smi -L
GPU 0: Tesla T4 (UUID: GPU-6a96a2af-2271-5627-34c5-91dcb4f408aa)

＃ Check that gVisor works with the GPU.
$ sudo docker run --rm --runtime=runsc --gpus=all nvidia/cuda:11.6.2-base-ubuntu20.04 nvidia-smi -L
GPU 0: Tesla T4 (UUID: GPU-6a96a2af-2271-5627-34c5-91dcb4f408aa)
```

We're all set! Now we can actually get Stable Diffusion running.

We used the following `Dockerfile` to run Stable Diffusion and its web UI within
a GPU-enabled Docker container.

```dockerfile
FROM python:3.10

＃ Set of dependencies that are needed to make this work.
RUN apt-get update && apt-get install -y git wget build-essential \
        nghttp2 libnghttp2-dev libssl-dev ffmpeg libsm6 libxext6
＃ Clone the project at the revision used for this test.
RUN git clone https://github.com/AUTOMATIC1111/stable-diffusion-webui.git && \
    cd /stable-diffusion-webui && \
    git checkout baf6946e06249c5af9851c60171692c44ef633e0
＃ We don't want the build step to start the server.
RUN sed -i '/start()/d' /stable-diffusion-webui/launch.py
＃ Install some pip packages.
＃ Note that this command will run as part of the Docker build process,
＃ which is *not* sandboxed by gVisor.
RUN cd /stable-diffusion-webui && COMMANDLINE_ARGS=--skip-torch-cuda-test python launch.py
WORKDIR /stable-diffusion-webui
＃ This causes the web UI to use the Gradio service to create a public URL.
＃ Do not use this if you plan on leaving the container running long-term.
ENV COMMANDLINE_ARGS=--share
＃ Start the webui app.
CMD ["python", "webui.py"]
```

We build the image and create a container with it using the `docker`
command-line.

```shell
$ cat > Dockerfile
(... Paste the above contents...)
^D
$ sudo docker build --tag=sdui .
```

Finally, we can start the Stable Diffusion web UI. Note that it will take a long
time to start, as it has to download all the models from the Internet. To keep
this post simple, we didn't set up any kind of volume that would enable data
persistence, so it will do this every time the container starts.

```shell
$ sudo docker run --runtime=runsc --gpus=all --name=sdui --detach sdui

＃ Follow the logs:
$ sudo docker logs -f sdui
＃ [...]
Calculating sha256 for /stable-diffusion-webui/models/Stable-diffusion/v1-5-pruned-emaonly.safetensors: Running on local URL:  http://127.0.0.1:7860
Running on public URL: https://4446d982b4129a66d7.gradio.live

This share link expires in 72 hours.
＃ [...]
```

We're all set! Now we can browse to the Gradio URL shown in the logs and start
generating pictures, all within the secure confines of gVisor.

![Stable Diffusion Web UI](/assets/images/2023-06-20-stable-diffusion-web-ui.png "Stable Diffusion UI."){:width="100%"}
<span class="attribution">**Stable Diffusion Web UI screenshot.** Inner image
generated with Stable Diffusion v1.5.</span>

Happy sandboxing!

![Astronaut showing thumbs up](/assets/images/2023-06-20-astronaut-thumbs-up.png "Astronaut showing thumbs up.")
<span class="attribution">**Happy sandboxing!** Generated with Stable Diffusion
v1.5.</span>

[gVisor GPU support]: https://github.com/google/gvisor/blob/master/g3doc/proposals/nvidia_driver_proxy.md
[Stable Diffusion]: https://stability.ai/blog/stable-diffusion-public-release
[Stability AI]: https://stability.ai/
[automatic1111/stable-diffusion-webui]: https://github.com/AUTOMATIC1111/stable-diffusion-webui
[Stable Diffusion Web UI extensions]: https://github.com/AUTOMATIC1111/stable-diffusion-webui-extensions/blob/master/index.json
[PyTorch]: https://pytorch.org/
[safetensors]: https://github.com/huggingface/safetensors
[Pickle format]: https://www.splunk.com/en_us/blog/security/paws-in-the-pickle-jar-risk-vulnerability-in-the-model-sharing-ecosystem.html
[Docker installation on Debian]: https://docs.docker.com/engine/install/debian/
[NVIDIA container toolkit]: https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/user-guide.html
[NVIDIA container toolkit installation]: https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html
[gVisor setup]: https://gvisor.dev/docs/user_guide/install/
