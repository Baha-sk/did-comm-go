/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httptransport

import (
	"github.com/trustbloc/did-comm-go/pkg/transport"
)

// this is a WIP implementation of Transport protocol.
type httpTransport struct {
}

// NewHTTPTransport provides a new HTTP transport
func NewHTTPTransport() transport.Transport {
	return &httpTransport{}
}

func (http *httpTransport) Send(data string) error {
	return nil
}
