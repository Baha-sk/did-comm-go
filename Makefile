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

unit-test: generate-test-keys
	@scripts/check_unit.sh

generate-test-keys: clean
	@scripts/openssl_env.sh scripts/generate_test_keys.sh

clean:
	rm -Rf test/fixtures/keys

.PHONY: all checks
