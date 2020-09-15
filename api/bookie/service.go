package bookie

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/common"
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
		host = os.Getenv("BOOKIE_API_PATH")
	}

	scheme := defaultBookiePath
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

// BroadcastPayment attempts to broadcast a payment using the given params
// FIXME-- this is a proof of concept for now...
func BroadcastPayment(token string, params map[string]interface{}) (map[string]interface{}, error) {
	status, resp, err := InitBookieService(common.StringOrNil(token)).Post("payments", params)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create payment; status: %v", status)
	}

	// FIXME...
	response := map[string]interface{}{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &response)

	if err != nil {
		return nil, fmt.Errorf("failed to create payment; status: %v; %s", status, err.Error())
	}

	return response, nil
}
