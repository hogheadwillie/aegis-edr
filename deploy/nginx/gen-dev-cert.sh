#!/bin/sh
# Generate a self-signed dev certificate for the Aegis nginx proxy.
# Lab use only — browsers will warn; use Let's Encrypt for anything real.
set -eu

openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes \
    -keyout /etc/ssl/private/aegis-dev.key \
    -out /etc/ssl/certs/aegis-dev.crt \
    -subj "/CN=aegis.local" \
    -addext "subjectAltName=DNS:aegis.local,DNS:localhost,IP:127.0.0.1"

chmod 600 /etc/ssl/private/aegis-dev.key
echo "Wrote /etc/ssl/certs/aegis-dev.crt and /etc/ssl/private/aegis-dev.key"
