#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

DOCKER_CMD=${DOCKER_CMD:-docker}

if [ ! $(command -v ${DOCKER_CMD}) ]; then
    exit 0
fi

echo "GolangCI Linter :: Started"

${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/goapp -e RUN=1 -e REPO=github.com/trustbloc/aries-framework-go golangci/build-runner goenvbuild

echo "GolangCI Linter :: Completed"
