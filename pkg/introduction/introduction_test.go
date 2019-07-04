/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduction

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/aries-framework-go/pkg/models/didexchange"
)

const destinationURL = "https://localhost:8090"

/*---------------Mock setup-----------------------*/
// MockOutboundTransport mock transport (implements OutboundTransport)
type MockOutboundTransport struct {
}

// NewMockOutboundTransport new MockOutboundTransport instance
func NewMockOutboundTransport() *MockOutboundTransport {
	return &MockOutboundTransport{}
}

// Send implementation of OutboundTransport.Send api
func (transport *MockOutboundTransport) Send(data string, destination string) (string, error) {
	if data == "" || destination == "" {
		return "", errors.New("Data or destination can't be empty")
	}

	return "success", nil
}

/*---------------Test-----------------------*/
func TestSendProposal(t *testing.T) {
	proposal := &didexchange.IntroductionProposal{
		ID: "aosjfl341kd45",
		To: &didexchange.IntroductionDescriptor{Name: "Bob"},
	}

	// positive case
	require.NoError(t, SendProposal(proposal, destinationURL, NewMockOutboundTransport()))

	// nil proposal
	require.Error(t, SendProposal(nil, destinationURL, NewMockOutboundTransport()))

	// nil destination
	require.Error(t, SendProposal(proposal, "", NewMockOutboundTransport()))

	// nil Descriptor
	proposal.To = nil
	require.Error(t, SendProposal(proposal, destinationURL, NewMockOutboundTransport()))

	// nil name inside the Descriptor
	proposal.To = &didexchange.IntroductionDescriptor{}
	require.Error(t, SendProposal(proposal, destinationURL, NewMockOutboundTransport()))
}

func TestSendRequest(t *testing.T) {
	request := &didexchange.IntroductionRequest{
		ID:          "aosjfl341kd45",
		IntroduceTo: &didexchange.RequestDescriptor{Name: "Bob"},
	}

	// positive case
	require.NoError(t, SendRequest(request, destinationURL, NewMockOutboundTransport()))

	// nil request
	require.Error(t, SendRequest(nil, destinationURL, NewMockOutboundTransport()))

	// nil destination
	require.Error(t, SendRequest(request, "", NewMockOutboundTransport()))

	// nil IntroduceTo
	request.IntroduceTo = nil
	require.Error(t, SendRequest(request, destinationURL, NewMockOutboundTransport()))

	// nil IntroduceTo name
	request.IntroduceTo = &didexchange.RequestDescriptor{}
	require.Error(t, SendRequest(request, destinationURL, NewMockOutboundTransport()))
}

func TestSendResponse(t *testing.T) {
	response := &didexchange.IntroductionResponse{
		ID:     "ofjkwfl930or20",
		Thread: &didexchange.Thread{ID: "aosjfl341kd45"},
	}

	// positive case
	require.NoError(t, SendResponse(response, destinationURL, NewMockOutboundTransport()))

	// nil response
	require.Error(t, SendResponse(nil, destinationURL, NewMockOutboundTransport()))

	// nil destination
	require.Error(t, SendResponse(response, "", NewMockOutboundTransport()))

	// nil thread
	response.Thread = nil
	require.Error(t, SendResponse(response, destinationURL, NewMockOutboundTransport()))

	// nil thread id
	response.Thread = &didexchange.Thread{}
	require.Error(t, SendResponse(response, destinationURL, NewMockOutboundTransport()))
}
