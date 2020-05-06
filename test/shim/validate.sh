#!/bin/bash

# A sample script to validate a running nginx container.

set -ex

{ # Step 1: Inspect the pod
sudo crictl inspectp ${SANDBOX_ID}
}

{ # Step 2: Inspect the container
sudo crictl inspect ${CONTAINER_ID}
}

{ # Step 3: Check dmesg
sudo crictl exec ${CONTAINER_ID} dmesg | grep -i gvisor
}
