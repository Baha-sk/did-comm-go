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

// SendInviteWithPublicDID sends the invite with public DID
func (comm *DIDComm) SendInviteWithPublicDID(id, label, did string) error {
	if id == "" && did == "" {
		return errors.New("id and DID are necessary to send the Invite message")
	}

	invitationJSON, err := json.Marshal(buildInvitationMessage(connectionInvite, id, label, did, nil, "", nil))
	if err != nil {
		return errors.Wrapf(err, "Marshal Send Invite message Error")
	}

	return comm.transport.Send(base64.URLEncoding.EncodeToString(invitationJSON), "https://localhost:8090") // TODO need to add destination url here
}

// SendInviteWithKeyAndURLEndpoint sends the invite with recipient key and URL endpoint
func (comm *DIDComm) SendInviteWithKeyAndURLEndpoint(id, label string, recipientKeys []string, serviceEndpoint string, routingKeys []string) error {
	if id == "" {
		return errors.New("id is necessary to send the Invite message")
	}

	invitationJSON, err := json.Marshal(buildInvitationMessage(connectionInvite, id, label, "", recipientKeys, serviceEndpoint, routingKeys))
	if err != nil {
		return errors.Wrapf(err, "Marshal Send Invite Message with Key and URL Error")
	}

	return comm.transport.Send(base64.URLEncoding.EncodeToString(invitationJSON), "https://localhost:8090") // same comment as above
}

// SendInviteWithKeyAndDIDServiceEndpoint sends the invite with recipient key and DID service endpoint
func (comm *DIDComm) SendInviteWithKeyAndDIDServiceEndpoint(id, label string, recipientKeys []string, serviceEndpoint string, routingKeys []string) error {
	if id == "" {
		return errors.New("id is necessary to send the Invite message")
	}

	invitationJSON, err := json.Marshal(buildInvitationMessage(connectionInvite, id, label, "", recipientKeys, serviceEndpoint, routingKeys))
	if err != nil {
		return errors.Wrapf(err, "Marshal Send Invite Message with Key and DID Service Endpoint Error")
	}

	return comm.transport.Send(base64.URLEncoding.EncodeToString(invitationJSON), "https://localhost:8090") // same comment as above
}

// SendExchangeRequest sends exchange request
func (comm *DIDComm) SendExchangeRequest(exchangeRequest *didexchange.Request) error {
	if exchangeRequest == nil {
		return errors.New("exchangeRequest cannot be nil")
	}
	exchangeRequest.Type = connectionRequest
	exchangeRequestJSON, err := json.Marshal(exchangeRequest)
	if err != nil {
		return errors.Wrapf(err, "Marshal Send Exchange Request Error")
	}

	return comm.transport.Send(string(exchangeRequestJSON), "https://localhost:8090") // same comment as above
}

// SendExchangeResponse sends exchange response
func (comm *DIDComm) SendExchangeResponse(exchangeResponse *didexchange.Response) error {
	if exchangeResponse == nil {
		return errors.New("exchangeResponse cannot be nil")
	}
	exchangeResponse.Type = connectionResponse
	exchangeResponseJSON, err := json.Marshal(exchangeResponse)
	if err != nil {
		return errors.Wrapf(err, "Marshal Send Exchange Response Error")
	}

	return comm.transport.Send(string(exchangeResponseJSON), "https://localhost:8090") // same comment as above
}

func buildInvitationMessage(messageType, id, label, did string, recipientKeys []string, serviceEndpoint string, routingKeys []string) *didexchange.InviteMessage {
	return &didexchange.InviteMessage{
		Type:            messageType,
		ID:              id,
		Label:           label,
		DID:             did,
		RecipientKeys:   recipientKeys,
		ServiceEndpoint: serviceEndpoint,
		RoutingKeys:     routingKeys,
	}
}
