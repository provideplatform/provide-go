package bookie

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/common"
)

const defaultBookieHost = "api.providepayments.com"
const defaultBookiePath = "api/v1"
const defaultBookieScheme = "https"

// Service for the ident api
type Service struct {
	api.Client
}

// InitBookieService convenience method to initialize a `bookie.Service` instance
func InitBookieService(token *string) *Service {
	host := defaultBookieHost
	if os.Getenv("BOOKIE_API_HOST") != "" {
		host = os.Getenv("BOOKIE_API_HOST")
	}

	path := defaultBookiePath
	if os.Getenv("BOOKIE_API_PATH") != "" {
		path = os.Getenv("BOOKIE_API_PATH")
	}

	scheme := defaultBookieScheme
	if os.Getenv("BOOKIE_API_SCHEME") != "" {
		scheme = os.Getenv("BOOKIE_API_SCHEME")
	}

	return &Service{
		api.Client{
			Host:   host,
			Path:   path,
			Scheme: scheme,
			Token:  token,
		},
	}
}

// CreatePayment attempts to create/broadcast a payment using the given params
// FIXME-- this is a proof of concept for now...
func CreatePayment(token string, params map[string]interface{}) (*Payment, error) {
	status, resp, err := InitBookieService(common.StringOrNil(token)).Post("payments", params)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create payment; status: %v", status)
	}

	// FIXME...
	payment := &Payment{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &payment)

	if err != nil {
		return nil, fmt.Errorf("failed to create payment; status: %v; %s", status, err.Error())
	}

	return payment, nil
}
