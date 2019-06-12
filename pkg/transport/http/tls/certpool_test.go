/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tls

import (
	"crypto/x509"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const certPrefix = "../test/fixtures/certs/"
const certPoolsPaths = certPrefix + "ec-pubCert1.pem," + certPrefix + "ec-pubCert2.pem," + certPrefix + "ec-pubCert3.pem,"

func TestNewCertPool(t *testing.T) {
	cp, err := NewCertPool(true)
	require.NoError(t, err)
	require.NotNil(t, cp)

	cp, err = NewCertPool(false)
	require.NoError(t, err)
	require.NotNil(t, cp)
}

func TestCertPool_AddAndDecodeAndGet(t *testing.T) {
	cp, err := NewCertPool(true)
	require.NoError(t, err)
	require.NotNil(t, cp)

	cp.Add(nil)
	cp.Add([]*x509.Certificate{}...)

	caCertsPaths := strings.Split(certPoolsPaths, ",")
	var caCerts []string
	for _, path := range caCertsPaths {
		if path == "" {
			continue
		}
		// Create a pool with server certificates
		caCert, e := ioutil.ReadFile(filepath.Clean(path))
		require.NoError(t, e)
		caCerts = append(caCerts, string(caCert))
	}

	cp.Add(DecodeCerts(caCerts)...)

	p, err := cp.Get()
	require.NoError(t, err)
	require.NotNil(t, p)

	cpLength1 := len(p.Subjects())

	// try adding the same certs again
	cp.Add(DecodeCerts(caCerts)...)
	p, err = cp.Get()
	require.NoError(t, err)
	require.NotNil(t, p)

	// ensure the same length of certs in the pool after adding the same certs again
	require.Equal(t, cpLength1, len(p.Subjects()))

	// test DecodeCerts with empty/bad certs
	certList := DecodeCerts([]string{"badCert", "", "-----BEGIN CERTIFICATE-----/nabcdde/n-----END CERTIFICATE-----", badCert})
	require.Empty(t, certList)
}

const badCert = `
-----BEGIN BADHEADER-----
MIICUjCCAbMCCQDoex4ibR3sAzAKBggqhkjOPQQDAjBtMQswCQYDVQQGEwJDQTEQ
MA4GA1UECAwHT250YXJpbzEQMA4GA1UEBwwHVG9yb250bzESMBAGA1UECgwJU2Vj
dXJla2V5MRIwEAYDVQQLDAlUcnVzdGJsb2MxEjAQBgNVBAMMCWxvY2FsaG9zdDAe
Fw0xOTA2MTIxNzEwMDdaFw0yMzA3MjExNzEwMDdaMG0xCzAJBgNVBAYTAkNBMRAw
DgYDVQQIDAdPbnRhcmlvMRAwDgYDVQQHDAdUb3JvbnRvMRIwEAYDVQQKDAlTZWN1
cmVrZXkxEjAQBgNVBAsMCVRydXN0YmxvYzESMBAGA1UEAwwJbG9jYWxob3N0MIGb
MBAGByqGSM49AgEGBSuBBAAjA4GGAAQAKBYfGtoj8Ub2CQcPMTJPjGxEJpejDZai
GeOGquleut7l4vI5jSS0EUb2z94q0AUTyehinRZQG+bgO6tJJJX0ZhUAI+4GPF19
jsgiTgnNT1r8RSCwJxqHuwNcg+lhmCLAYdSK5QCX+mqtmAiMlU/H0rLCLUqpZ1Xn
Z86aPTAhpVWOKbowCgYIKoZIzj0EAwIDgYwAMIGIAkIBNaKDYJniHiXJVp1kRji8
0hEKm/InkYfEMRA41gLn9teCoa8fjGGeW1oV4mUbXfoe9a+vMUoZd4sWMa8q3Hp4
RAkCQgFjHELih1AzHHOsHYYufgJnnLRt9G7O1vKp6fMs9em04kUVJuJ4jcjvmgCi
kgH86YyW04JBlWRgDBzO3lVEhyLRCg==
-----END BADHEADER-----
`
