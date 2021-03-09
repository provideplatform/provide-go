package privacy

import (
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideservices/provide-go/api"
)

// Circuit model
type Circuit struct {
	*api.Model

	Name          *string `json:"name"`
	Description   *string `json:"description"`
	Identifier    *string `json:"identifier"`
	Provider      *string `json:"provider"`
	ProvingScheme *string `json:"proving_scheme"`
	Curve         *string `json:"curve"`

	StoreID          *uuid.UUID             `json:"store_id"`
	Aritfacts        map[string]interface{} `json:"artifacts,omitempty"`
	VerifierContract map[string]interface{} `json:"verifier_contract,omitempty"`
}

// StoreValueResponse model
type StoreValueResponse struct {
	Errors   []*api.Error           `json:"errors,omitempty"`
	Root     *string                `json:"root,omitempty"`
	Value    *string                `json:"value"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ProveResponse model
type ProveResponse struct {
	Errors []*api.Error `json:"errors,omitempty"`
	Proof  *string      `json:"proof"`
}

// VerificationResponse model
type VerificationResponse struct {
	Errors []*api.Error `json:"errors,omitempty"`
	Result bool         `json:"result"`
}
