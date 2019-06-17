/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didbasic

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBasicProvider(t *testing.T) {
	didProv := NewProvider()

	didInfo, err := didProv.CreateLocalDID(nil)
	require.NoError(t, err)
	require.NotEmpty(t, didInfo.DID)

	_, err = didProv.CreateLocalDID(nil)
	require.NoError(t, err)

	didInfoBasedOnDID, err := didProv.GetLocalDIDInfo(didInfo.DID)
	require.NoError(t, err)
	require.Equal(t, didInfoBasedOnDID.VerKey, didInfo.VerKey)

	didInfoList, err := didProv.GetLocalDIDList()
	require.NoError(t, err)
	require.Equal(t, len(didInfoList), 2)

	didInfoBasedOnVerKey, err := didProv.GetLocalDIDBasedOnVerKey(didInfo.VerKey)
	require.NoError(t, err)
	require.Equal(t, didInfo.DID, didInfoBasedOnVerKey.DID)

	_, err = didProv.GetLocalDIDInfo("")
	require.Error(t, err)

	_, err = didProv.GetLocalDIDBasedOnVerKey(nil)
	require.Error(t, err)

}
