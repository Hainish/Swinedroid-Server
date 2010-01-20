#!/bin/bash
mkdir ssl
cd ssl
openssl genrsa -out server.key 4096
yes "" | openssl req -new -key server.key -out server.csr
openssl x509 -req -days 99999 -in server.csr -signkey server.key -out server.crt
