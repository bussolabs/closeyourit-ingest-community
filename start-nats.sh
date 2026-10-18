#!/bin/sh
set -eu

password_file=/run/secrets/nats_password
if [ ! -s "$password_file" ]; then
  echo "Secret NATS assente o vuoto" >&2
  exit 1
fi

NATS_PASSWORD="$(cat "$password_file")"
export NATS_PASSWORD

exec /usr/local/bin/nats-server --config /etc/nats/nats-server.conf
