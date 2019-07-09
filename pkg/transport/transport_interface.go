/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

// OutboundTransport interface definition for transport layer
// This is the client side of the agent
type OutboundTransport interface {
	// Send send a2a exchange data
	Send(data string, destination string) (string, error)
}

// RequestRouter struct for path and handler function
type RequestRouter struct {
	Path        string
	HandlerFunc func([]byte) error
}

// DIDCommHandler struct to pass details for request handlers
type DIDCommHandler struct {
	RecieveInvitation *RequestRouter
	ExchangeRequest   *RequestRouter
	ExchangeResponse  *RequestRouter
}
