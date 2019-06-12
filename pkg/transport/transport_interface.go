/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

// Transport interface definition for transport layer
// This is a WIP interface.
type Transport interface {
	// Send send a2a exchange data
	Send(data string) error
}
