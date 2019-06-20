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

// DIDComm supports DID communication apis
type DIDComm struct {
	transport transport.OutboundTransport
}

// NewDIDComm creates new instance of DID Communication
func NewDIDComm(transport transport.OutboundTransport) *DIDComm {
	return &DIDComm{transport: transport}
}

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
func (comm *DIDComm) SendExchangeRequest(exchangeRequest *didexchange.Request, destination string) error {
	if exchangeRequest == nil {
		return errors.New("exchangeRequest cannot be nil")
	}
	exchangeRequest.Type = connectionRequest
	exchangeRequestJSON, err := json.Marshal(exchangeRequest)
	if err != nil {
		return errors.Wrapf(err, "Marshal Send Exchange Request Error")
	}

	return comm.transport.Send(string(exchangeRequestJSON), destination)
}

// SendExchangeResponse sends exchange response
func (comm *DIDComm) SendExchangeResponse(exchangeResponse *didexchange.Response, destination string) error {
	if exchangeResponse == nil {
		return errors.New("exchangeResponse cannot be nil")
	}
	exchangeResponse.Type = connectionResponse
	exchangeResponseJSON, err := json.Marshal(exchangeResponse)
	if err != nil {
		return errors.Wrapf(err, "Marshal Send Exchange Response Error")
	}

	return comm.transport.Send(string(exchangeResponseJSON), destination)
}

func encodedExchangeInvitation(inviteMessage *didexchange.InviteMessage) (string, error) {
	inviteMessage.Type = connectionInvite

	invitationJSON, err := json.Marshal(inviteMessage)
	if err != nil {
		return "", errors.Wrapf(err, "JSON Marshal Error")
	}

	return base64.URLEncoding.EncodeToString(invitationJSON), nil
}
