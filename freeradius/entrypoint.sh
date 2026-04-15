#!/bin/bash
set -e

SECRET="${SHARED_SECRET:-ch4ng3m3}"
FGT_IP="${FORTIGATE_IP:-127.0.0.1}"

# Substitute placeholders in config files at runtime.
sed -i "s|%%SHARED_SECRET%%|${SECRET}|g"  /etc/freeradius/clients.conf
sed -i "s|%%FORTIGATE_IP%%|${FGT_IP}|g"   /etc/freeradius/clients.conf
sed -i "s|%%SHARED_SECRET%%|${SECRET}|g"  /etc/freeradius/mods-config/files/authorize

echo "[entrypoint] Configured client: ${FGT_IP}"

echo "[entrypoint] FreeRADIUS starting with shared secret configured."

exec freeradius -f -l stdout
