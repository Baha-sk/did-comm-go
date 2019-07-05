/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduction

import (
	"testing"

	"github.com/stretchr/testify/require"
	mock "github.com/trustbloc/aries-framework-go/pkg/mocks"
	"github.com/trustbloc/aries-framework-go/pkg/models/didexchange"
)

const destinationURL = "https://localhost:8090"
const successResponse = "success"

/*---------------Test-----------------------*/
func TestSendProposal(t *testing.T) {
	transport := mock.NewOutboundTransport(successResponse)

	proposal := &didexchange.IntroductionProposal{
		ID: "aosjfl341kd45",
		To: &didexchange.IntroductionDescriptor{Name: "Bob"},
	}

	// positive case
	require.NoError(t, SendProposal(proposal, destinationURL, transport))

	// nil proposal
	require.Error(t, SendProposal(nil, destinationURL, transport))

	// nil destination
	require.Error(t, SendProposal(proposal, "", transport))

	// nil Descriptor
	proposal.To = nil
	require.Error(t, SendProposal(proposal, destinationURL, transport))

	// nil name inside the Descriptor
	proposal.To = &didexchange.IntroductionDescriptor{}
	require.Error(t, SendProposal(proposal, destinationURL, transport))
}

func TestSendRequest(t *testing.T) {
	transport := mock.NewOutboundTransport(successResponse)

	request := &didexchange.IntroductionRequest{
		ID:          "aosjfl341kd45",
		IntroduceTo: &didexchange.RequestDescriptor{Name: "Bob"},
	}

	// positive case
	require.NoError(t, SendRequest(request, destinationURL, transport))

	// nil request
	require.Error(t, SendRequest(nil, destinationURL, transport))

	// nil destination
	require.Error(t, SendRequest(request, "", transport))

	// nil IntroduceTo
	request.IntroduceTo = nil
	require.Error(t, SendRequest(request, destinationURL, transport))

	// nil IntroduceTo name
	request.IntroduceTo = &didexchange.RequestDescriptor{}
	require.Error(t, SendRequest(request, destinationURL, transport))
}

func TestSendResponse(t *testing.T) {
	transport := mock.NewOutboundTransport(successResponse)

	response := &didexchange.IntroductionResponse{
		ID:     "ofjkwfl930or20",
		Thread: &didexchange.Thread{ID: "aosjfl341kd45"},
	}

	// positive case
	require.NoError(t, SendResponse(response, destinationURL, transport))

	// nil response
	require.Error(t, SendResponse(nil, destinationURL, transport))

	// nil destination
	require.Error(t, SendResponse(response, "", transport))

	// nil thread
	response.Thread = nil
	require.Error(t, SendResponse(response, destinationURL, transport))

	// nil thread id
	response.Thread = &didexchange.Thread{}
	require.Error(t, SendResponse(response, destinationURL, transport))
}
