/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import "github.com/trustbloc/did-common-go/pkg/diddoc"

// InviteMessage defines a2a invite message
type InviteMessage struct {
	Type            string   `json:"@type,omitempty"`
	ID              string   `json:"@id,omitempty"`
	Label           string   `json:"label,omitempty"`
	DID             string   `json:"did,omitempty"`
	RecipientKeys   []string `json:"recipientKeys,omitempty"`
	ServiceEndpoint string   `json:"serviceEndpoint,omitempty"`
	RoutingKeys     []string `json:"routingKeys,omitempty"`
}

// Request defines a2a exchange request
type Request struct {
	Type       string      `json:"@type,omitempty"`
	ID         string      `json:"@id,omitempty"`
	Label      string      `json:"label,omitempty"`
	Connection *Connection `json:"connection,omitempty"`
}

// Response defines a2a exchange response
type Response struct {
	Type                string               `json:"@type,omitempty"`
	ID                  string               `json:"@id,omitempty"`
	ConnectionSignature *ConnectionSignature `json:"connection~sig,omitempty"`
	Thread              *Thread              `json:"~thread,omitempty"`
}

// Thread thread data
type Thread struct {
	ID string `json:"@thid,omitempty"`
}

// ConnectionSignature connection signature
type ConnectionSignature struct {
	Type       string `json:"@type,omitempty"`
	Signature  string `json:"signature,omitempty"`
	SignedData string `json:"sig_data,omitempty"`
	SignVerKey string `json:"signers,omitempty"`
}

// Connection connection
type Connection struct {
	DID    string         `json:"did,omitempty"`
	DIDDoc *diddoc.DIDDoc `json:"did_doc,omitempty"`
}
