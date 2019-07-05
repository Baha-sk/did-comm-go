/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"testing"

	"github.com/stretchr/testify/require"
	mock "github.com/trustbloc/aries-framework-go/pkg/mocks"
	"github.com/trustbloc/aries-framework-go/pkg/models/didexchange"
)

const destinationURL = "https://localhost:8090"
const successResponse = "success"

func TestGenerateInviteWithPublicDID(t *testing.T) {
	invite, err := GenerateInviteWithPublicDID(&didexchange.InviteMessage{
		ID:    "12345678900987654321",
		Label: "Alice",
		DID:   "did:trustbloc:ZadolSRQkehfo",
	})

	require.NotEmpty(t, invite)

	invite, err = GenerateInviteWithPublicDID(&didexchange.InviteMessage{
		ID:    "12345678900987654321",
		Label: "Alice",
	})
	require.Error(t, err)
	require.Empty(t, invite)

	invite, err = GenerateInviteWithPublicDID(&didexchange.InviteMessage{
		Label: "Alice",
		DID:   "did:trustbloc:ZadolSRQkehfo",
	})
	require.Error(t, err)
	require.Empty(t, invite)
}

func TestGenerateInviteWithKeyAndEndpoint(t *testing.T) {
	invite, err := GenerateInviteWithKeyAndEndpoint(&didexchange.InviteMessage{
		ID:              "12345678900987654321",
		Label:           "Alice",
		RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.NotEmpty(t, invite)

	invite, err = GenerateInviteWithKeyAndEndpoint(&didexchange.InviteMessage{
		Label:           "Alice",
		RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.Error(t, err)
	require.Empty(t, invite)

	invite, err = GenerateInviteWithKeyAndEndpoint(&didexchange.InviteMessage{
		ID:            "12345678900987654321",
		Label:         "Alice",
		RecipientKeys: []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		RoutingKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.Error(t, err)
	require.Empty(t, invite)

	invite, err = GenerateInviteWithKeyAndEndpoint(&didexchange.InviteMessage{
		ID:              "12345678900987654321",
		Label:           "Alice",
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.Error(t, err)
	require.Empty(t, invite)
}

func TestSendRequest(t *testing.T) {
	oTr := mock.NewOutboundTransport(successResponse)

	req := &didexchange.Request{
		ID:    "5678876542345",
		Label: "Bob",
	}

	require.NoError(t, SendExchangeRequest(req, destinationURL, oTr))
	require.Error(t, SendExchangeRequest(nil, destinationURL, oTr))
}

func TestSendResponse(t *testing.T) {
	oTr := mock.NewOutboundTransport(successResponse)

	resp := &didexchange.Response{
		ID: "12345678900987654321",
		ConnectionSignature: &didexchange.ConnectionSignature{
			Type: "did:trustbloc:RQkehfoFssiwQRuihskwoPSR;spec/ed25519Sha512_single/1.0/ed25519Sha512_single",
		},
	}

	require.NoError(t, SendExchangeResponse(resp, destinationURL, oTr))
	require.Error(t, SendExchangeResponse(nil, destinationURL, oTr))
}
