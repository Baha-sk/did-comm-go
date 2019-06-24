/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/trustbloc/did-comm-go/pkg/models/didexchange"
	"github.com/trustbloc/did-comm-go/pkg/transport"
)

const (
	connectionInvite   = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation"
	connectionRequest  = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/request"
	connectionResponse = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/response"
)

// GenerateInviteWithPublicDID generates the DID exchange invitation string with public DID
func GenerateInviteWithPublicDID(inviteMessage *didexchange.InviteMessage) (string, error) {
	if inviteMessage.ID == "" || inviteMessage.DID == "" {
		return "", errors.New("ID and DID are mandatory")
	}

	return encodedExchangeInvitation(inviteMessage)
}

// GenerateInviteWithKeyAndEndpoint generates the DID exchange invitation string with recipient key and endpoint
func GenerateInviteWithKeyAndEndpoint(inviteMessage *didexchange.InviteMessage) (string, error) {
	if inviteMessage.ID == "" || inviteMessage.ServiceEndpoint == "" || len(inviteMessage.RecipientKeys) == 0 {
		return "", errors.New("ID, Service Endpoint and Recipient Key are mandatory")
	}

	return encodedExchangeInvitation(inviteMessage)
}

// SendExchangeRequest sends exchange request
func SendExchangeRequest(exchangeRequest *didexchange.Request, destination string, transport transport.OutboundTransport) error {
	if exchangeRequest == nil {
		return errors.New("exchangeRequest cannot be nil")
	}
	exchangeRequest.Type = connectionRequest
	exchangeRequestJSON, err := json.Marshal(exchangeRequest)
	if err != nil {
		return errors.Wrapf(err, "Marshal Send Exchange Request Error")
	}

	_, err = transport.Send(string(exchangeRequestJSON), destination)
	return err
}

// SendExchangeResponse sends exchange response
func SendExchangeResponse(exchangeResponse *didexchange.Response, destination string, transport transport.OutboundTransport) error {
	if exchangeResponse == nil {
		return errors.New("exchangeResponse cannot be nil")
	}
	exchangeResponse.Type = connectionResponse
	exchangeResponseJSON, err := json.Marshal(exchangeResponse)
	if err != nil {
		return errors.Wrapf(err, "Marshal Send Exchange Response Error")
	}

	_, err = transport.Send(string(exchangeResponseJSON), destination)
	return err
}

func encodedExchangeInvitation(inviteMessage *didexchange.InviteMessage) (string, error) {
	inviteMessage.Type = connectionInvite

	invitationJSON, err := json.Marshal(inviteMessage)
	if err != nil {
		return "", errors.Wrapf(err, "JSON Marshal Error")
	}

	return base64.URLEncoding.EncodeToString(invitationJSON), nil
}
