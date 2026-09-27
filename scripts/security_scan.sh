#!/usr/bin/env bash
set -euo pipefail

# Git Bash rewrites Unix-looking Docker mount paths unless conversion is disabled.
# These variables are harmless on Linux runners and keep local Windows validation
# aligned with the CI environment.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

workspace="$(pwd -P)"
scan_directory="${workspace}/data/security-scan"
case "${scan_directory}" in
  "${workspace}"/*) ;;
  *) echo "Temporary scan directory must remain inside the workspace." >&2; exit 1 ;;
esac

mkdir -p "${scan_directory}"
archive="${scan_directory}/api-rootfs.tar"
docker_workspace="${workspace}"
docker_scan_directory="${scan_directory}"
docker_archive="${archive}"
if command -v cygpath >/dev/null 2>&1; then
  docker_workspace="$(cygpath -m "${workspace}")"
  docker_scan_directory="$(cygpath -m "${scan_directory}")"
  docker_archive="$(cygpath -m "${archive}")"
fi
scan_id="${RANDOM}-$$"
scan_container="osint-trivy-export-${scan_id}"
rootfs_volume="osint-trivy-rootfs-${scan_id}"
scan_image="osint-ai-framework-api:security-scan"

cleanup() {
  docker rm -f "${scan_container}" >/dev/null 2>&1 || true
  docker volume rm -f "${rootfs_volume}" >/dev/null 2>&1 || true
  rm -f "${archive}"
}
trap cleanup EXIT

docker build \
  --provenance=false \
  --sbom=false \
  --target runtime \
  --tag "${scan_image}" \
  .
docker create --name "${scan_container}" "${scan_image}" >/dev/null
docker export --output "${docker_archive}" "${scan_container}"
docker volume create "${rootfs_volume}" >/dev/null
docker run --rm \
  --mount "type=bind,source=${docker_scan_directory},target=/scan,readonly" \
  -v "${rootfs_volume}:/rootfs" \
  alpine:3.23 \
  tar -xf /scan/api-rootfs.tar -C /rootfs
rm -f "${archive}"

docker run --rm \
  -v trivy_cache:/root/.cache/ \
  -v "${rootfs_volume}:/rootfs:ro" \
  aquasec/trivy:0.74.0 rootfs /rootfs \
  --scanners vuln \
  --exit-code 1 \
  --severity HIGH,CRITICAL \
  --ignore-unfixed

docker run --rm \
  -v trivy_cache:/root/.cache/ \
  --mount "type=bind,source=${docker_workspace},target=/workspace,readonly" \
  aquasec/trivy:0.74.0 fs /workspace \
  --scanners secret \
  --exit-code 1
