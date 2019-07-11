/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWithResultType(t *testing.T) {
	opt := WithResultType(DidDocumentResult)
	resolveOpts := &resolveOpts{}
	opt(resolveOpts)
	require.Equal(t, DidDocumentResult, resolveOpts.resultType)
}

func TestWithVersionID(t *testing.T) {
	opt := WithVersionID("v1")
	resolveOpts := &resolveOpts{}
	opt(resolveOpts)
	versionID := resolveOpts.versionID.(string)
	require.Equal(t, "v1", versionID)
}

func TestWithVersionTime(t *testing.T) {
	timeNow := time.Now()
	opt := WithVersionTime(timeNow)
	resolveOpts := &resolveOpts{}
	opt(resolveOpts)
	require.Equal(t, timeNow.Format(time.RFC3339), resolveOpts.versionTime)
}

func TestWithNoCache(t *testing.T) {
	opt := WithNoCache(true)
	resolveOpts := &resolveOpts{}
	opt(resolveOpts)
	require.True(t, resolveOpts.noCache)
}

func TestWithDidMethod(t *testing.T) {
	opt := WithDidMethod("test", nil)
	resolverOpts := &resolverOpts{didMethods: make(map[string]didMethod)}
	opt(resolverOpts)
	_, exist := resolverOpts.didMethods["test"]
	require.True(t, exist)
}
