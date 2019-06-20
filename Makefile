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
	@mkdir -p -p test/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/go/src/github.com/trustbloc/did-comm-go \
		--entrypoint "/opt/go/src/github.com/trustbloc/did-comm-go/scripts/generate_test_keys.sh" \
		frapsoft/openssl

clean:
	rm -Rf ./test

.PHONY: all checks
