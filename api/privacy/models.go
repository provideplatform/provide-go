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

// VerificationResponse model
type VerificationResponse struct {
}
