package privacy

import (
	"github.com/provideservices/provide-go/api"
)

// Circuit model
type Circuit struct {
	*api.Model

	Name             *string `json:"name"`
	Description      *string `json:"description"`
	Type             *string `json:"type"`
	Curve            *string `json:"curve"`
	ConstraintSystem *string `json:"constraint_system"`
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
