/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-comm-go/pkg/models/didexchange"
	httptransport "github.com/trustbloc/did-comm-go/pkg/transport/http"
)

func TestSendInviteWithPublicDID(t *testing.T) {
	didComm := NewDIDComm(httptransport.NewHTTPTransport())

	require.NoError(t, didComm.SendInviteWithPublicDID(
		"12345678900987654321",
		"Alice",
		"did:trustbloc:ZadolSRQkehfo",
	))
}

func TestSendInviteWithKeyAndURLEndpoint(t *testing.T) {
	didComm := NewDIDComm(httptransport.NewHTTPTransport())

	require.NoError(t, didComm.SendInviteWithKeyAndURLEndpoint(
		"12345678900987654321",
		"Alice",
		[]string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		"https://example.com/endpoint",
		[]string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"}))
}

func TestSendInviteWithKeyAndDIDServiceEndpoint(t *testing.T) {
	didComm := NewDIDComm(httptransport.NewHTTPTransport())

	require.NoError(t, didComm.SendInviteWithKeyAndDIDServiceEndpoint(
		"12345678900987654321",
		"Alice",
		[]string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		"did:trustbloc:ZadolSRQkehfo;service=routeid",
		[]string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"}))
}

func TestSendRequest(t *testing.T) {
	didComm := NewDIDComm(httptransport.NewHTTPTransport())

	req := &didexchange.Request{
		ID:    "5678876542345",
		Label: "Bob",
	}

	require.NoError(t, didComm.SendExchangeRequest(req))
}

func TestSendResponse(t *testing.T) {
	didComm := NewDIDComm(httptransport.NewHTTPTransport())

	resp := &didexchange.Response{
		ID: "12345678900987654321",
		ConnectionSignature: &didexchange.ConnectionSignature{
			Type: "did:trustbloc:RQkehfoFssiwQRuihskwoPSR;spec/ed25519Sha512_single/1.0/ed25519Sha512_single",
		},
	}

	require.NoError(t, didComm.SendExchangeResponse(resp))
}
