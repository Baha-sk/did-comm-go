/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

var doc = `{
  "@context": "https://w3id.org/did/v1",
  "publicKey": [
    {
      "id": "#key1",
      "type": "Secp256k1VerificationKey2018",
      "publicKeyJwk": {
        "kty": "EC",
        "kid": "key1",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc",
        "use": "verify",
        "defaultEncryptionAlgorithm": "none"
      }
    },
    {
      "id": "#key2",
      "type": "RsaVerificationKey2018",
      "publicKeyPem": "-----BEGIN PUBLIC KEY.2.END PUBLIC KEY-----"
    }
  ],
  "service": [
    {
      "id": "IdentityHub",
      "type": "IdentityHub",
      "serviceEndpoint": {
        "@context": "schema.identity.foundation/hub",
        "@type": "UserServiceEndpoint",
        "instance": [
          "did:test:456",
          "did:test:789"
        ]
      }
    }
  ]
}`

func TestNew(t *testing.T) {
	r := New(WithDidMethod("test", nil))
	_, exist := r.didMethods["test"]
	require.True(t, exist)
}

func TestResolve(t *testing.T) {
	t.Run("test invalid did input", func(t *testing.T) {
		r := New(WithDidMethod("test", nil))
		_, err := r.Resolve("did:example")
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrong format did input")
	})

	t.Run("test did method not supported", func(t *testing.T) {
		r := New(WithDidMethod("test", nil))
		_, err := r.Resolve("did:example:1234")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method example not supported")
	})

	t.Run("test did method read failed", func(t *testing.T) {
		r := New(WithDidMethod("example", mockDidMethod{readErr: fmt.Errorf("read error")}))
		_, err := r.Resolve("did:example:1234")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method read failed")
	})

	t.Run("test did input not found", func(t *testing.T) {
		r := New(WithDidMethod("example", mockDidMethod{}))
		didDoc, err := r.Resolve("did:example:1234")
		require.NoError(t, err)
		require.Nil(t, didDoc)
	})

	t.Run("test result type resolution-result", func(t *testing.T) {
		r := New(WithDidMethod("example", mockDidMethod{readValue: []byte(doc)}))
		_, err := r.Resolve("did:example:1234", WithResultType(ResolutionResult))
		require.Error(t, err)
		require.Contains(t, err.Error(), "result type 'resolution-result' not supported")
	})

	t.Run("test result type did-document", func(t *testing.T) {
		r := New(WithDidMethod("example", mockDidMethod{readValue: []byte(doc)}))
		didDoc, err := r.Resolve("did:example:1234", WithResultType(DidDocumentResult))
		require.NoError(t, err)
		require.Equal(t, didDoc["@context"], "https://w3id.org/did/v1")
	})
}

type mockDidMethod struct {
	readValue []byte
	readErr   error
}

func (m mockDidMethod) Read(did string, versionID interface{}, versionTime string, noCache bool) ([]byte, error) {
	return m.readValue, m.readErr
}
