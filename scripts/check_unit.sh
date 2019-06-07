#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

# Packages to exclude
PKGS=`go list github.com/trustbloc/did-comm-go/... 2> /dev/null | \
                                                 grep -v /mocks | \
                                                 grep -v /protos`

echo "Unit test :: Started"

go test $PKGS -count=1 -race -coverprofile=coverage.txt -covermode=atomic  -p 1 -timeout=10m

echo "Unit test :: Completed"