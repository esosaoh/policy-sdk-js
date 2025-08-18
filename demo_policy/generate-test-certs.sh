#!/bin/bash

mkdir -p test_data/certs

# Generate a valid certificate
openssl req -x509 -newkey rsa:2048 -keyout test_data/certs/test.key \
  -out test_data/certs/valid-cert.pem -days 365 -nodes \
  -subj "/CN=TestCA"

# Convert PEM to DER for your handler
openssl x509 -outform der -in test_data/certs/valid-cert.pem \
  -out test_data/certs/valid-cert.der