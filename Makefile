# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GO_CMD ?= go
GO111MODULE=on

all: checks unit-test

checks: license lint

lint:
	@scripts/check_lint.sh

license:
	@scripts/check_license.sh

unit-test:
	@scripts/check_unit.sh

.PHONY: all checks
