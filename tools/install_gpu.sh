#!/bin/bash

# Copyright 2023 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euxo pipefail

echo "$(python --version || /bin/true)"
echo "$(python3 --version || /bin/true)"
echo "$(gcc --version || /bin/true)"
echo "$(clang --version || /bin/true)"

BASE_URL=https://us.download.nvidia.com/tesla

DRIVER_VERSION="${1:?"Specify a driver version!"}"

# No need to install the driver if the correct one is installed.
if  [[ -e /usr/bin/nvidia-smi && $(nvidia-smi | grep "${DRIVER_VERSION}") ]];then
        echo "Correct driver ${DRIVER_VERSION} already present!"
        # Print out driver version.
        /usr/bin/nvidia-smi
        exit 0
fi

# If we already have another driver installed, uninstall the previous driver.
if [[ -e /usr/bin/nvidia-uninstall ]]; then
        sudo /usr/bin/nvidia-uninstall -s
fi

sudo apt -y update && sudo apt -y install gcc-12
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 12
export LLVM=1 && export LLVM_IS=1 && export IGNORE_CC_MISMATCH=1
curl -fSsl -O "${BASE_URL}/${DRIVER_VERSION}/NVIDIA-Linux-x86_64-${DRIVER_VERSION}.run"
sudo sh "NVIDIA-Linux-x86_64-${DRIVER_VERSION}.run" --dkms -a -s --no-drm --install-libglvnd '' || cat /var/log/nvidia-installer.log
rm "NVIDIA-Linux-x86_64-$DRIVER_VERSION.run"

# Print out driver version.
/usr/bin/nvidia-smi
