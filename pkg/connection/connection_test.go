/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"net/http"
	"testing"
	"time"

	"log"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-comm-go/pkg/models/didexchange"
	httptransport "github.com/trustbloc/did-comm-go/pkg/transport/http"
)

const certPrefix = "../../test/fixtures/keys/"
const certPoolsPaths = certPrefix + "ec-pubCert1.pem," + certPrefix + "ec-pubCert2.pem," + certPrefix + "ec-pubCert3.pem,"
const clientTimeout = 10 * time.Second
const destinationURL = "https://localhost:8090"

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
	oCommConfig := &httptransport.OutboundCommConfig{
		Timeout:      clientTimeout,
		CACertsPaths: certPoolsPaths,
	}
	oTr, err := httptransport.NewOutboundCommFromConfig(oCommConfig)
	require.NoError(t, err)

	req := &didexchange.Request{
		ID:    "5678876542345",
		Label: "Bob",
	}

	require.NoError(t, SendExchangeRequest(req, destinationURL, oTr))
	require.Error(t, SendExchangeRequest(nil, destinationURL, oTr))
}

func TestSendResponse(t *testing.T) {
	oCommConfig := &httptransport.OutboundCommConfig{
		Timeout:      clientTimeout,
		CACertsPaths: certPoolsPaths,
	}
	oTr, err := httptransport.NewOutboundCommFromConfig(oCommConfig)
	require.NoError(t, err)

	resp := &didexchange.Response{
		ID: "12345678900987654321",
		ConnectionSignature: &didexchange.ConnectionSignature{
			Type: "did:trustbloc:RQkehfoFssiwQRuihskwoPSR;spec/ed25519Sha512_single/1.0/ed25519Sha512_single",
		},
	}

	require.NoError(t, SendExchangeResponse(resp, destinationURL, oTr))
	require.Error(t, SendExchangeResponse(nil, destinationURL, oTr))
}

func TestMain(m *testing.M) {
	mh := httptransport.DidCommHandler(mockHttpHandler{})

	httpServer := &http.Server{
		Addr:    ":8090",
		Handler: mh,
	}

	go func() {
		err := httpServer.ListenAndServeTLS(certPrefix+"ec-pubCert1.pem", certPrefix+"ec-key1.pem")
		if err != nil && err.Error() != "http: Server closed" {
			log.Fatalf("HTTP server failed to start: %v", err)
		}
	}()
	rc := m.Run()

	err := httpServer.Close()
	if err != nil {
		log.Fatalf("Failed to stop server: %s, integration test results: %d", err, rc)
	}
}

type mockHttpHandler struct {
	mux *http.ServeMux
}

func (m mockHttpHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	m.serve(res, req)
}

func (m *mockHttpHandler) serve(res http.ResponseWriter, req *http.Request) {
	// mocking successful response
	res.WriteHeader(http.StatusAccepted)
}
