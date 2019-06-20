#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Generating DidComm-go Test PKI"
cd /opt/go/src/github.com/trustbloc/did-comm-go
mkdir -p test/fixtures/keys/tls

cp /etc/ssl/openssl.cnf test/fixtures/keys/openssl.cnf
echo -e "[SAN]\nsubjectAltName=DNS:*.example.com,DNS:localhost" >> test/fixtures/keys/openssl.cnf

#create CA for TLS creds
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/keys/tls/ec-cakey.pem
openssl req -new -x509 -key test/fixtures/keys/tls/ec-cakey.pem -subj "/C=CA/ST=ON/O=Example Internet CA TLS Inc.:CA Sec/OU=CA Sec" -out test/fixtures/keys/tls/ec-cacert.pem

#create TLS creds
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/keys/tls/ec-key.pem
openssl req -new -key test/fixtures/keys/tls/ec-key.pem -subj "/C=CA/ST=ON/O=Example Inc.:DidComm-go/OU=DidComm-go/CN=*.example.com" -reqexts SAN -config test/fixtures/keys/openssl.cnf -out test/fixtures/keys/tls/ec-key.csr
openssl x509 -req -in test/fixtures/keys/tls/ec-key.csr -extensions SAN -extfile test/fixtures/keys/openssl.cnf -CA test/fixtures/keys/tls/ec-cacert.pem -CAkey test/fixtures/keys/tls/ec-cakey.pem -CAcreateserial -out test/fixtures/keys/tls/ec-pubCert.pem -days 365

#create CA for other creds
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/keys/ec-cakey.pem
openssl req -new -x509 -key test/fixtures/keys/ec-cakey.pem -subj "/C=CA/ST=ON/O=Example Internet CA Inc.:CA Sec/OU=CA Sec" -out test/fixtures/keys/ec-cacert.pem

#create creds 1
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/keys/ec-key1.pem
openssl req -new -key test/fixtures/keys/ec-key1.pem -subj "/C=CA/ST=ON/O=Example Inc.:DidComm-go/OU=DidComm-go/CN=*.example.com" -reqexts SAN -config test/fixtures/keys/openssl.cnf -out test/fixtures/keys/ec-key1.csr
openssl x509 -req -in test/fixtures/keys/ec-key1.csr -extensions SAN -extfile test/fixtures/keys/openssl.cnf -CA test/fixtures/keys/ec-cacert.pem -CAkey test/fixtures/keys/ec-cakey.pem -CAcreateserial -out test/fixtures/keys/ec-pubCert1.pem -days 365

#create creds 2
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/keys/ec-key2.pem
openssl req -new -key test/fixtures/keys/ec-key2.pem -subj "/C=CA/ST=ON/O=Example Inc.:DidComm-go/OU=DidComm-go/CN=*.example.com" -reqexts SAN -config test/fixtures/keys/openssl.cnf -out test/fixtures/keys/ec-key2.csr
openssl x509 -req -in test/fixtures/keys/ec-key2.csr -extensions SAN -extfile test/fixtures/keys/openssl.cnf -CA test/fixtures/keys/ec-cacert.pem -CAkey test/fixtures/keys/ec-cakey.pem -CAcreateserial -out test/fixtures/keys/ec-pubCert2.pem -days 365

#create creds 3
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/keys/ec-key3.pem
openssl req -new -key test/fixtures/keys/ec-key3.pem -subj "/C=CA/ST=ON/O=Example Inc.:DidComm-go/OU=DidComm-go/CN=*.example.com" -reqexts SAN -config test/fixtures/keys/openssl.cnf -out test/fixtures/keys/ec-key3.csr
openssl x509 -req -in test/fixtures/keys/ec-key3.csr -extensions SAN -extfile test/fixtures/keys/openssl.cnf -CA test/fixtures/keys/ec-cacert.pem -CAkey test/fixtures/keys/ec-cakey.pem -CAcreateserial -out test/fixtures/keys/ec-pubCert3.pem -days 365

rm test/fixtures/keys/openssl.cnf
echo "done generating DidComm-go PKI"