#!/bin/bash

# Copyright 2019 The gVisor Authors.
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

source $(dirname $0)/common.sh

make load-packetimpact

install_runsc_for_test runsc-d
cat << EOF >> ~/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDGM4g3ujfOE4Qnymepa8rPnR9mC4oSVUe2+1N1rQVNFtOVcJkNnqSKSmXRMQ4m4cxO30VAz8l5EKIZt95XY8G0+k0pgY3F884FPpsRskqaOpuEqc48GgoW8AEe9f1mtWYPZpZt4lOzHh+QAruchwPxiyKzGy/IOMLFmsdI2RDGGURZvQvih/RZXQlTFdZg2hcR667OQAwryiA0QD79DE8swzq+VfmGDskzOsOhECknBQu6FHYJEyntaKDyYPkCUhH6l41A52Fi8oMyXKKtFTfCx2MU158hoyX8t2MH+t5xouEw/d80FwSbgkt01wy3+I+RKhdps2WsqMUUx+rSwguTwWyD2rn0sxPQWmyLhSjSS74rrtuImeVaKRheuTQ5+ycmBn8pdvC48nvdXt2iBrDPmdf6LskURmv3jAEeuwczOjMadMLOYq0usQLZlxRObzEZ0XVELK/YOdpZnSo0SxHXGlyq6oH0LmxL62rqGQNKminxg3RZpqFOUKv9N+3XjB8=
EOF

external_ip=$(curl -s -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)
echo "To connect: ssh -i <your private key file> kbuilder@${external_ip}"
sleep 3600

test_runsc $(bazel query "attr(tags, packetimpact, tests(//test/packetimpact/...))")
