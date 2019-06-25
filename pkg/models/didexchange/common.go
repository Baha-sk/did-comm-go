/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

// Thread thread data
type Thread struct {
	ID string `json:"@thid,omitempty"`
}

// ImageAttachment structure for image attachment data
type ImageAttachment struct {
	Description string        `json:"@description,omitempty"`
	MIMEType    string        `json:"@mime-type,omitempty"`
	FileName    string        `json:"@filename,omitempty"`
	Content     *ImageContent `json:"@content,omitempty"`
}

// ImageContent image content data
type ImageContent struct {
	Link      string `json:"@link,omitempty"`
	ByteCount string `json:"@byte_count,omitempty"`
	SHA256    string `json:"@sha256,omitempty"`
}

// Time time related data structure
type Time struct {
	Expires string `json:"@expires_time,omitempty"`
}

// Localization localization data structure
type Localization struct {
	Locale  string `json:"@locale,omitempty"`
	Message string `json:"@es,omitempty"`
}
