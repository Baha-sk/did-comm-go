/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

// LocalDIDInfo structure for local DID Information. Primarily used for storing/passing keypair and metadata for a DID
type LocalDIDInfo struct {
	DID      string
	VerKey   []byte
	Secret   []byte
	Metadata map[string]interface{}
}

// Provider API provided by DID Providers
type Provider interface {
	// CreateLocalDID create a new DID along with keypair and stores info along with metadata.
	CreateLocalDID(metadata map[string]interface{}) (*LocalDIDInfo, error)

	// GetLocalDIDInfo fetch DID info based on DID
	GetLocalDIDInfo(did string) (*LocalDIDInfo, error)

	// GetLocalDIDList fetches all the stored DID LocalDIDInfo
	GetLocalDIDList() ([]*LocalDIDInfo, error)

	// GetLocalDIDBasedOnVerKey fetch DID info based on VerKey
	GetLocalDIDBasedOnVerKey(verkey []byte) (*LocalDIDInfo, error)
}
