#!/bin/sh
set -e
mkdir -p /etc/nginx/certs
if [ ! -f /etc/nginx/certs/server.crt ] || [ ! -f /etc/nginx/certs/server.key ]; then
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout /etc/nginx/certs/server.key \
    -out /etc/nginx/certs/server.crt \
    -days 1 \
    -subj "/CN=gateway"
fi
exec nginx -g 'daemon off;'
