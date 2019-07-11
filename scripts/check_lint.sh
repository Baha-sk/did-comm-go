#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

DOCKER_CMD=${DOCKER_CMD:-docker}
GOLANGCI_LINT_VERSION=v1.16.0

if [ ! $(command -v ${DOCKER_CMD}) ]; then
    exit 0
fi

echo "GolangCI Linter :: Started"

${DOCKER_CMD} run -v $(pwd):/opt/workspace -w /opt/workspace golangci/golangci-lint:${GOLANGCI_LINT_VERSION} golangci-lint run

echo "GolangCI Linter :: Completed"
