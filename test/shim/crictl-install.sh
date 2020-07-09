#!/bin/bash

# A sample script for installing crictl.

set -ex

{ # Step 1: Download crictl
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.13.0/crictl-v1.13.0-linux-amd64.tar.gz
tar xf crictl-v1.13.0-linux-amd64.tar.gz
sudo mv crictl /usr/local/bin
}

{ # Step 2: Configure crictl
cat <<EOF | sudo tee /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
EOF
}
