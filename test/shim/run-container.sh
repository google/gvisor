#!/bin/bash

# A sample script to run a container in an existing pod

set -ex

{ # Step 1: Create nginx container config
cat <<EOF | tee container.json
{
  "metadata": {
      "name": "nginx"
    },
  "image":{
      "image": "nginx"
    },
  "log_path":"nginx.0.log",
  "linux": {
  }
}
EOF
}

{ # Step 2: Create nginx container
CONTAINER_ID=$(sudo crictl create ${SANDBOX_ID} container.json sandbox.json)
}

{ # Step 3: Start nginx container
sudo crictl start ${CONTAINER_ID}
}

