#!/usr/bin/env bash

set -x
# openssl genrsa -out ca.key 2048
# openssl req -x509 -sha256 -new -nodes -key ca.key -days 3650 -out ca.pem  \
#    -subj "/C=CA/O=test/OU=test/CN=*.knative-restore.svc"

# openssl genrsa -out webhook.key 2048

# openssl req -new -key webhook.key -sha256 -out webhook.csr -config webhook.config \
#   -extensions 'v3_req'

# openssl x509 -req -sha256 -in webhook.csr -CA ca.pem -CAkey ca.key \
#   -CAcreateserial -out webhook.pem -days 365


# cat ca.pem | base64 -w 0


cat > ca-config.json <<EOF
{
  "signing": {
    "default": {
      "expiry": "8760h"
    },
    "profiles": {
      "server": {
        "usages": ["signing", "key encipherment", "server auth", "client auth"],
        "expiry": "8760h"
      }
    }
  }
}
EOF

cat > ca-csr.json <<EOF
{
  "CN": "Kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "CA",
      "ST": "Oregon"
    }
  ]
}
EOF

cat > server-csr.json <<EOF
{
  "CN": "admission",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "Kubernetes",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert -initca ca-csr.json | cfssljson -bare ca

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -hostname=webhook-owner-references.knative-restore.svc \
  -profile=server \
  server-csr.json | cfssljson -bare server

rm ca-config.json
rm ca-csr.json
rm server-csr.json

cat ca.pem | base64 -w 0
