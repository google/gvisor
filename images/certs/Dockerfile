# Generates the a CA cert, a server key, and a server cert signed by the CA.
# reference:
# https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/pkg/admission/plugin/webhook/testcerts/gencerts.sh
FROM ubuntu:18.04
WORKDIR /certs
ADD server.conf /conf/server.conf
# Install openssl.
RUN apt-get update && apt-get install -y openssl
# Create all certificates.
CMD openssl genrsa -out caKey.pem 2048 && \
    openssl req -x509 -new -nodes -key caKey.pem -days 100000 -out caCert.pem -subj "/CN=e2e_ca" -config /conf/server.conf && \
    openssl genrsa -out serverKey.pem 2048 && \
    openssl req -new -key serverKey.pem -out server.csr -subj "/CN=gvisor-injection-admission-webhook.e2e.svc" -config /conf/server.conf && \
    openssl x509 -req -in server.csr -CA caCert.pem -CAkey caKey.pem -CAcreateserial -out serverCert.pem -days 100000 -extensions v3_req -extfile /conf/server.conf
