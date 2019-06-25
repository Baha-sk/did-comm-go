/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduction

import (
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/trustbloc/aries-framework-go/pkg/models/didexchange"
	"github.com/trustbloc/aries-framework-go/pkg/transport"
)

const (
	introduceProposal = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/introduce/1.0/proposal"
	introduceRequest  = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/introduce/1.0/request"
	introduceResponse = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/introduce/1.0/response"
)

// SendProposal sends the introduction proposal
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0028-introduce#proposal-1
func SendProposal(proposal *didexchange.IntroductionProposal, destination string, transport transport.OutboundTransport) error {
	if proposal == nil {
		return errors.New("proposal cannot be nil")
	}
	if proposal.ID == "" || proposal.To == nil || proposal.To.Name == "" {
		return errors.New("Proposal id and introducee descriptor name are mandatory")
	}

	proposal.Type = introduceProposal
	_, err := marshalAndSend(proposal, "Error Marshalling Send Introduction Proposal", destination, transport)
	return err
}

// SendRequest sends the introduction request
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0028-introduce#request
func SendRequest(request *didexchange.IntroductionRequest, destination string, transport transport.OutboundTransport) error {
	if request == nil {
		return errors.New("Request cannot be nil")
	}
	if request.ID == "" || request.IntroduceTo == nil || request.IntroduceTo.Name == "" {
		return errors.New("Request id and introducee descriptor name are mandatory")
	}

	request.Type = introduceRequest
	_, err := marshalAndSend(request, "Error Marshalling Send Introduction Request", destination, transport)
	return err
}

// SendResponse sends the introduction response
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0028-introduce#response
func SendResponse(response *didexchange.IntroductionResponse, destination string, transport transport.OutboundTransport) error {
	if response == nil {
		return errors.New("Response cannot be nil")
	}
	if response.ID == "" || response.Thread == nil || response.Thread.ID == "" {
		return errors.New("Response id and thread id are mandatory")
	}

	response.Type = introduceResponse
	_, err := marshalAndSend(response, "Error Marshalling Send Introduction Response", destination, transport)
	return err
}

func marshalAndSend(data interface{}, errorMsg, destination string, transport transport.OutboundTransport) (string, error) {
	jsonString, err := json.Marshal(data)
	if err != nil {
		return "", errors.Wrapf(err, errorMsg)
	}
	return transport.Send(string(jsonString), destination)
}
