/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

// IntroductionProposal introduction proposal structure
type IntroductionProposal struct {
	Type  string                  `json:"@type,omitempty"`
	ID    string                  `json:"@id,omitempty"`
	To    *IntroductionDescriptor `json:"to,omitempty"`
	NWise bool                    `json:"@nwise,omitempty"`
	Time  *Time                   `json:"@~timing,omitempty"`
}

// IntroductionResponse introduction response structure
type IntroductionResponse struct {
	Type       string         `json:"@type,omitempty"`
	ID         string         `json:"@id,omitempty"`
	Thread     *Thread        `json:"~thread,omitempty"`
	Approve    bool           `json:"@approve,omitempty"`
	Invitation *InviteMessage `json:"@invitation,omitempty"`
}

// IntroductionDescriptor introducee descriptor structure
type IntroductionDescriptor struct {
	Name                 string           `json:"@name,omitempty"`
	Description          string           `json:"@description,omitempty"`
	LocalizedDescription *Localization    `json:"~description~l10n,omitempty"`
	Where                string           `json:"@where,omitempty"`
	ImageAttachment      *ImageAttachment `json:"@img~attach,omitempty"`
	Proposed             bool             `json:"@proposed,omitempty"`
}

// IntroductionRequest introduction request structure
type IntroductionRequest struct {
	Type        string             `json:"@type,omitempty"`
	ID          string             `json:"@id,omitempty"`
	IntroduceTo *RequestDescriptor `json:"please_introduce_to,omitempty"`
	NWise       bool               `json:"@nwise,omitempty"`
	Timing      *Time              `json:"@~timing,omitempty"`
}

// RequestDescriptor descriptor structure
type RequestDescriptor struct {
	Name        string `json:"@name,omitempty"`
	Description string `json:"@description,omitempty"`
	Expected    bool   `json:"@expected,omitempty"`
}
