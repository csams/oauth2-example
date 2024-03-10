#!/usr/bin/env bash

podman run \
    --rm \
    --name keycloak \
    -p 8080:8080 \
    -e KEYCLOAK_ADMIN=admin \
    -e KEYCLOAK_ADMIN_PASSWORD=admin \
    --security-opt label=disable \
    --mount=type=bind,src=realm-data,dst=/opt/keycloak/data/import,U \
    quay.io/keycloak/keycloak:22.0.5-0 \
    start-dev \
    --import-realm

