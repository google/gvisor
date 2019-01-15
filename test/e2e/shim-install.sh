#!/bin/bash

# A sample script to install gvisor-containerd-shim

set -ex

# Build gvisor-containerd-shim
if [ "${INSTALL_LATEST}" === "1" ]; then
{ # Step 1: Download gvisor-containerd-shim
LATEST_RELEASE=$(wget -qO - https://api.github.com/repos/google/gvisor-containerd-shim/releases | grep -oP '(?<="browser_download_url": ")https://[^"]*' | head -1)
wget -O gvisor-containerd-shim
chmod +x gvisor-containerd-shim
}
else
    make
    mv bin/gvisor-containerd-shim gvisor-containerd-shim-dev
fi

{ # Step 2: Copy the binary to the desired directory
sudo mv gvisor-containerd-shim-* /usr/local/bin/gvisor-containerd-shim
}


{ # Step 3: Create the gvisor-containerd-shim.yaml
cat <<EOF | sudo tee /etc/containerd/gvisor-containerd-shim.yaml
# This is the path to the default runc containerd-shim.
runc_shim = "/usr/local/bin/containerd-shim"
EOF
}

