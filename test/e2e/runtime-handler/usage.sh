#!/bin/bash

# A sample script for testing the gvisor-containerd-shim
# using runtime handler.

set -ex

{ # Step 1: Pull the nginx image
sudo crictl pull nginx
}

{ # Step 2: Create sandbox.json
cat <<EOF | tee sandbox.json
{
    "metadata": {
        "name": "nginx-sandbox",
        "namespace": "default",
        "attempt": 1,
        "uid": "hdishd83djaidwnduwk28bcsb"
    },
    "linux": {
    },
    "log_directory": "/tmp"
}
EOF
}

{ # Step 3: Create the sandbox
SANDBOX_ID=$(sudo crictl runp --runtime runsc sandbox.json)
}
