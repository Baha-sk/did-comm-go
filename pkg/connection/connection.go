/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

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
	transport transport.Transport
}

// NewDIDComm creates new instance of DID Communication
func NewDIDComm(transport transport.Transport) *DIDComm {
	return &DIDComm{transport: transport}
}

// SendInviteWithPublicDID sends the invite with public DID
func (comm *DIDComm) SendInviteWithPublicDID(id, label, did string) error {
	invitationJSON, err := json.Marshal(buildInvitationMessage(connectionInvite, id, label, did, nil, "", nil))
	if err != nil {
		panic(fmt.Sprintf("JSON Marshal Error : %s", err))
	}

	return comm.transport.Send(base64.URLEncoding.EncodeToString(invitationJSON))
}

// SendInviteWithKeyAndURLEndpoint sends the invite with recipient key and URL endpoint
func (comm *DIDComm) SendInviteWithKeyAndURLEndpoint(id, label string, recipientKeys []string, serviceEndpoint string, routingKeys []string) error {
	invitationJSON, err := json.Marshal(buildInvitationMessage(connectionInvite, id, label, "", recipientKeys, serviceEndpoint, routingKeys))
	if err != nil {
		panic(fmt.Sprintf("JSON Marshal Error : %s", err))
	}

	return comm.transport.Send(base64.URLEncoding.EncodeToString(invitationJSON))
}

// SendInviteWithKeyAndDIDServiceEndpoint sends the invite with recipient key and DID service endpoint
func (comm *DIDComm) SendInviteWithKeyAndDIDServiceEndpoint(id, label string, recipientKeys []string, serviceEndpoint string, routingKeys []string) error {
	invitationJSON, err := json.Marshal(buildInvitationMessage(connectionInvite, id, label, "", recipientKeys, serviceEndpoint, routingKeys))
	if err != nil {
		panic(fmt.Sprintf("JSON Marshal Error : %s", err))
	}

	return comm.transport.Send(base64.URLEncoding.EncodeToString(invitationJSON))
}

// SendExchangeRequest sends exchange request
func (comm *DIDComm) SendExchangeRequest(exchangeRequest *didexchange.Request) error {
	exchangeRequest.Type = connectionRequest
	exchangeRequestJSON, err := json.Marshal(exchangeRequest)
	if err != nil {
		panic(fmt.Sprintf("JSON Marshal Error : %s", err))
	}

	return comm.transport.Send(string(exchangeRequestJSON))
}

// SendExchangeResponse sends exchange response
func (comm *DIDComm) SendExchangeResponse(exchangeResponse *didexchange.Response) error {
	exchangeResponse.Type = connectionResponse
	exchangeResponseJSON, err := json.Marshal(exchangeResponse)
	if err != nil {
		panic(fmt.Sprintf("JSON Marshal Error : %s", err))
	}

	return comm.transport.Send(string(exchangeResponseJSON))
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
