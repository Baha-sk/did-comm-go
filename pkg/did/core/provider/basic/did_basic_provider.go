/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didbasic

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	didprovider "github.com/trustbloc/aries-framework-go/pkg/did/core/provider"
)

// Provider provider structure
type Provider struct {
	store map[string]*didprovider.LocalDIDInfo
	lock  sync.RWMutex
}

// NewProvider instance of Basic DID provider
func NewProvider() *Provider {
	return &Provider{
		store: map[string]*didprovider.LocalDIDInfo{},
	}
}

// CreateLocalDID create a new DID along with keypair and stores info along with metadata.
func (prov *Provider) CreateLocalDID(metadata map[string]interface{}) (*didprovider.LocalDIDInfo, error) {
	didInfo := &didprovider.LocalDIDInfo{
		// (TO-DO) : generate unique DID
		DID: time.Now().String(),
		// (TO-DO) : generate keypair
		VerKey:   []byte(time.Now().String()),
		Secret:   []byte(time.Now().String()),
		Metadata: metadata,
	}

	// store DID LocalDIDInfo (in-memory)
	prov.lock.Lock()
	prov.store[didInfo.DID] = didInfo
	prov.lock.Unlock()

	return didInfo, nil
}

// GetLocalDIDInfo fetch DID info based on DID
func (prov *Provider) GetLocalDIDInfo(did string) (*didprovider.LocalDIDInfo, error) {
	prov.lock.RLock()
	defer prov.lock.RUnlock()
	val, ok := prov.store[did]
	if !ok {
		return nil, fmt.Errorf("No Local DID Info found for DID %s", did)
	}

	return val, nil
}

// GetLocalDIDList fetches all the stored DID LocalDIDInfo
func (prov *Provider) GetLocalDIDList() ([]*didprovider.LocalDIDInfo, error) {
	prov.lock.RLock()
	defer prov.lock.RUnlock()

	dids := make([]*didprovider.LocalDIDInfo, 0, len(prov.store))
	for _, value := range prov.store {
		dids = append(dids, value)
	}

	return dids, nil
}

// GetLocalDIDBasedOnVerKey fetch DID info based on VerKey
func (prov *Provider) GetLocalDIDBasedOnVerKey(verkey []byte) (*didprovider.LocalDIDInfo, error) {
	prov.lock.RLock()
	defer prov.lock.RUnlock()

	for _, value := range prov.store {
		if reflect.DeepEqual(value.VerKey, verkey) {
			return value, nil
		}
	}

	return nil, errors.New("No Local DID Info found for VerKey")
}
