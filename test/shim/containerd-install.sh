#!/bin/bash

# A script to install containerd and CNI plugins for e2e testing

wget -q --https-only \
    https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-${CONTAINERD_VERSION}.linux-amd64.tar.gz \
    https://github.com/containernetworking/plugins/releases/download/v0.7.0/cni-plugins-amd64-v0.7.0.tgz

sudo mkdir -p /etc/containerd /etc/cni/net.d /opt/cni/bin
sudo tar -xvf cni-plugins-amd64-v0.7.0.tgz -C /opt/cni/bin/
sudo tar -xvf containerd-${CONTAINERD_VERSION}.linux-amd64.tar.gz -C /

cat <<EOF | sudo tee /etc/containerd/config.toml
disabled_plugins = ["restart"]
# Set to avoid port overlap on older versions of containerd where default is 10010.
[plugins.cri]
  stream_server_port = "10011"
EOF

cat <<EOF | sudo tee /etc/cni/net.d/10-bridge.conf
{
  "cniVersion": "0.3.1",
  "name": "bridge",
  "type": "bridge",
  "bridge": "cnio0",
  "isGateway": true,
  "ipMasq": true,
  "ipam": {
      "type": "host-local",
      "ranges": [
        [{"subnet": "10.200.0.0/24"}]
      ],
      "routes": [{"dst": "0.0.0.0/0"}]
  }
}
EOF
cat <<EOF | sudo tee /etc/cni/net.d/99-loopback.conf
{
  "cniVersion": "0.3.1",
  "type": "loopback"
}
EOF

sudo PATH=$PATH containerd -log-level debug &>/tmp/containerd-cri.log &
