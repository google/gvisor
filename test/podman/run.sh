#!/bin/bash

set -u -x -e -o pipefail

test_dir=$(mktemp -d /tmp/gvisor-podman.XXXXXX)
podman_runtime=${test_dir}/runsc.podman

cleanup() {
        rm -rf ${test_dir}
}
trap cleanup EXIT

make copy TARGETS=runsc DESTINATION=$test_dir
cat > ${podman_runtime} <<EOF
#!/bin/bash

exec $test_dir/runsc --ignore-cgroups --network host --debug --debug-log ${test_dir}/runsc.log "\$@"
EOF
chmod ugo+x ${podman_runtime}
chmod ugo+x ${test_dir}/runsc
chmod ugo+xwr ${test_dir}
cat /etc/passwd | grep  podman-testuser || \
adduser   --disabled-login  --disabled-password podman-testuser < /dev/null
( 
        cd /
        sudo -u testuser5 podman run --runtime ${podman_runtime} alpine echo Hello, world
)
