# -*- mode: ruby -*-
# vi: set ft=ruby :

# Fedora box is used for testing cgroup v2 support
Vagrant.configure("2") do |config|
  config.vm.box = "fedora/33-cloud-base"

  config.vm.synced_folder ".", "/vagrant", type: "rsync",
    rsync__exclude: [".git/", "bazel-bin/", "bazel-gvisor/", "bazel-out/", "bazel-testlogs/"]

  memory = 4096
  cpus = 2
  config.vm.provider :virtualbox do |v|
    v.memory = memory
    v.cpus = cpus
  end
  config.vm.provider :libvirt do |v|
    v.memory = memory
    v.cpus = cpus
  end

  config.vm.provision "install-bazel", type: "shell", run: "once", inline: <<-SHELL
    set -e -u -o pipefail
    # Work around dnf mirror failures by retrying a few times
    dnf install -y dnf-plugins-core
    dnf copr enable -y vbatts/bazel
    dnf install -y make bazel3 gcc golang-go
  SHELL

  config.vm.provision "install-docker", type: "shell", run: "once", inline: <<-SHELL
    set -e -u -o pipefail
    dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
    dnf install -y docker-ce docker-ce-cli containerd.io

    systemctl daemon-reload

    # tell docker to not use systemd cgroup as that is not supported now
    echo '{"exec-opts": ["native.cgroupdriver=cgroupfs"]}' > /etc/docker/daemon.json

    systemctl enable docker
    systemctl restart docker
    usermod -aG docker vagrant
  SHELL
end
