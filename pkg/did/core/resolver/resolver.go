/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/trustbloc/aries-framework-go/pkg/did/core/document"
)

// Resolver did resolver
type Resolver struct {
	didMethods map[string]didMethod
}

// New return new instance of resolver
func New(opts ...Opt) *Resolver {
	resolverOpts := &resolverOpts{didMethods: make(map[string]didMethod)}
	// Apply options
	for _, opt := range opts {
		opt(resolverOpts)
	}
	return &Resolver{didMethods: resolverOpts.didMethods}
}

// Resolve did document
func (r *Resolver) Resolve(did string, opts ...ResolveOpt) (map[string]interface{}, error) {
	resolveOpts := &resolveOpts{}
	// Apply options
	for _, opt := range opts {
		opt(resolveOpts)
	}

	// TODO Validate that the input DID conforms to the did rule of the Generic DID Syntax (https://w3c-ccg.github.io/did-spec/#generic-did-syntax)
	// For now we do simple validation
	didParts := strings.SplitN(did, ":", 3)
	if len(didParts) != 3 {
		return nil, errors.New("wrong format did input")
	}

	// Determine if the input DID method is supported by the DID Resolver
	didMethod := didParts[1]
	method, exist := r.didMethods[didMethod]
	if !exist {
		return nil, errors.Errorf("did method %s not supported", didMethod)
	}

	// Obtain the DID Document
	didDocBytes, err := method.Read(did, resolveOpts.versionID, resolveOpts.versionTime, resolveOpts.noCache)
	if err != nil {
		return nil, errors.Wrapf(err, "did method read failed")
	}

	// If the input DID does not exist, return a nil
	if len(didDocBytes) == 0 {
		return nil, nil
	}

	// Validate that the output DID Document conforms to the serialization of the DID Document data model
	didDoc, err := document.DidDocumentFromBytes(didDocBytes)
	if err != nil {
		return nil, err
	}

	if resolveOpts.resultType == ResolutionResult {
		// TODO Support resolution-result
		return nil, errors.New("result type 'resolution-result' not supported")
	}

	return didDoc.JSONLdObject(), nil
}
