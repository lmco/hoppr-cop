#!/bin/bash

set -euo pipefail

IMAGES=$(kubectl get pods --all-namespaces -o json | jq -r '.items[].spec.containers[].image' | sort |uniq)

SYFT_BIN="podman run -v ${PWD}:/workdir -w /workdir docker.io/anchore/syft:latest"
GRYPE_BIN="podman run -v ${PWD}:/workdir -w /workdir docker.io/anchore/grype:latest"

for IMAGE in ${IMAGES}; do
    IMAGE_FILE_BASE="$(echo "${IMAGE}" | tr -s ':' '/')"
    IMAGE_FILE_SBOM="sbom/${IMAGE_FILE_BASE}.sbom.json"
    IMAGE_FILE_VULN="vuln/${IMAGE_FILE_BASE}.vuln.txt"
    mkdir -p $(dirname "${IMAGE_FILE_SBOM}")
    ${SYFT_BIN} packages registry:${IMAGE} -o json --file "${IMAGE_FILE_SBOM}"
    mkdir -p $(dirname "${IMAGE_FILE_VULN}")
    ${GRYPE_BIN} "sbom:${IMAGE_FILE_SBOM}" --file "${IMAGE_FILE_VULN}" --add-cpes-if-none
done
