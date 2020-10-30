#!/bin/bash

# Copyright 2020 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# Generates the a CA cert, a server key, and a server cert signed by the CA.
# reference:
# https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/pkg/admission/plugin/webhook/testcerts/gencerts.sh
set -euo pipefail

# Do all the work in TMPDIR, then copy out generated code and delete TMPDIR.
declare -r OUTDIR="$(readlink -e .)"
declare -r TMPDIR="$(mktemp -d)"
cd "${TMPDIR}"
function cleanup() {
  cd "${OUTDIR}"
  rm -rf "${TMPDIR}"
}
trap cleanup EXIT

declare -r CN_BASE="e2e"
declare -r CN="gvisor-injection-admission-webhook.e2e.svc"

cat > server.conf << EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
EOF

declare -r OUTFILE="${TMPDIR}/certs.go"

# We depend on OpenSSL being present.

# Create a certificate authority.
openssl genrsa -out caKey.pem 2048
openssl req -x509 -new -nodes -key caKey.pem -days 100000 -out caCert.pem -subj "/CN=${CN_BASE}_ca" -config server.conf

# Create a server certificate.
openssl genrsa -out serverKey.pem 2048
# Note the CN is the DNS name of the service of the webhook.
openssl req -new -key serverKey.pem -out server.csr -subj "/CN=${CN}" -config server.conf
openssl x509 -req -in server.csr -CA caCert.pem -CAkey caKey.pem -CAcreateserial -out serverCert.pem -days 100000 -extensions v3_req -extfile server.conf

echo "package injector" > "${OUTFILE}"
echo "" >> "${OUTFILE}"
echo "// This file was generated using openssl by the gencerts.sh script." >> "${OUTFILE}"
for file in caKey caCert serverKey serverCert; do
  DATA=$(cat "${file}.pem")
  echo "" >> "${OUTFILE}"
  echo "var $file = []byte(\`$DATA\`)" >> "${OUTFILE}"
done

# Copy generated code into the output directory.
cp "${OUTFILE}" "${OUTDIR}/$1"
