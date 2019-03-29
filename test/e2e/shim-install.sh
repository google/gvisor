#!/bin/bash

# A sample script to install gvisor-containerd-shim

set -ex

# Build gvisor-containerd-shim
if [ "${INSTALL_LATEST}" == "1" ]; then
{ # Step 1(release): Install gvisor-containerd-shim
LATEST_RELEASE=$(wget -qO - https://api.github.com/repos/google/gvisor-containerd-shim/releases | grep -oP '(?<="browser_download_url": ")https://[^"]*gvisor-containerd-shim.linux-amd64' | head -1)
wget -O gvisor-containerd-shim ${LATEST_RELEASE}
chmod +x gvisor-containerd-shim
sudo mv gvisor-containerd-shim /usr/local/bin/gvisor-containerd-shim
}
else
{ # Step 1(dev): Build and install gvisor-containerd-shim and containerd-shim-runsc-v1
    make
    sudo make install
}
fi

{ # Step 2: Create the gvisor-containerd-shim.toml
cat <<EOF | sudo tee /etc/containerd/gvisor-containerd-shim.toml
# This is the path to the default runc containerd-shim.
runc_shim = "/usr/local/bin/containerd-shim"
EOF
}

