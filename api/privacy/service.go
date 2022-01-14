package privacy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/common"
)

const defaultPrivacyHost = "privacy.provide.services"
const defaultPrivacyPath = "api/v1"
const defaultPrivacyScheme = "https"

// Service for the privacy api
type Service struct {
	api.Client
}

// InitPrivacyService convenience method to initialize a `privacy.Service` instance
func InitPrivacyService(token string) *Service {
	host := defaultPrivacyHost
	if os.Getenv("PRIVACY_API_HOST") != "" {
		host = os.Getenv("PRIVACY_API_HOST")
	}

	path := defaultPrivacyPath
	if os.Getenv("PRIVACY_API_PATH") != "" {
		host = os.Getenv("PRIVACY_API_PATH")
	}

	scheme := defaultPrivacyScheme
	if os.Getenv("PRIVACY_API_SCHEME") != "" {
		scheme = os.Getenv("PRIVACY_API_SCHEME")
	}

	return &Service{
		api.Client{
			Host:   host,
			Path:   path,
			Scheme: scheme,
			Token:  common.StringOrNil(token),
		},
	}
}

// ListCircuits lists the circuits in the scope of the given bearer token
func ListCircuits(token string, params map[string]interface{}) ([]*Circuit, *common.Response, error) {
	status, resp, err := InitPrivacyService(token).GetPaginated("circuits", params)
	if err != nil {
		return nil, nil, err
	}

	if status != 200 {
		return nil, nil, fmt.Errorf("failed to list circuits; status: %v", status)
	}

	circuits := make([]*Circuit, 0)
	for _, item := range resp.Results.([]interface{}) {
		circuit := &Circuit{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &circuit)
		circuits = append(circuits, circuit)
	}

	response := &common.Response{
		TotalCount: resp.TotalCount,
	}
	return circuits, response, nil
}

// GetCircuitDetails fetches details for the given circuit
func GetCircuitDetails(token, circuitID string) (*Circuit, error) {
	uri := fmt.Sprintf("circuits/%s", circuitID)
	status, resp, err := InitPrivacyService(token).Get(uri, map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch circuit; status: %v", status)
	}

	circuit := &Circuit{}
	raw, _ := json.Marshal(resp)
	json.Unmarshal(raw, &circuit)

	return circuit, nil
}

// CreateCircuit creates a new circuit in the registry
func CreateCircuit(token string, params map[string]interface{}) (*Circuit, error) {
	status, resp, err := InitPrivacyService(token).Post("circuits", params)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create circuit; status: %v", status)
	}

	circuit := &Circuit{}
	raw, _ := json.Marshal(resp)
	json.Unmarshal(raw, &circuit)

	return circuit, nil
}

// Prove generates a proof using the given inputs for the named circuit
func Prove(token, circuitID string, params map[string]interface{}) (*ProveResponse, error) {
	uri := fmt.Sprintf("circuits/%s/prove", circuitID)
	status, resp, err := InitPrivacyService(token).Post(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 && status != 201 && status != 202 {
		return nil, fmt.Errorf("failed to generate proof; status: %v", status)
	}

	prove := &ProveResponse{}
	raw, _ := json.Marshal(resp)
	json.Unmarshal(raw, &prove)

	return prove, nil
}

// Verify verifies the given inputs using the named circuit
func Verify(token, circuitID string, params map[string]interface{}) (*VerificationResponse, error) {
	uri := fmt.Sprintf("circuits/%s/verify", circuitID)
	status, resp, err := InitPrivacyService(token).Post(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 && status != 202 {
		return nil, fmt.Errorf("failed to verify circuit inputs; status: %v", status)
	}

	verification := &VerificationResponse{}
	raw, _ := json.Marshal(resp)
	json.Unmarshal(raw, &verification)

	return verification, nil
}

// GetNoteValue fetches the value in the note store at a specified index
func GetNoteValue(token, circuitID string, index uint64) (*StoreValueResponse, error) {
	uri := fmt.Sprintf("circuits/%s/notes/%d", circuitID, index)
	status, resp, err := InitPrivacyService(token).Get(uri, map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	if status != 200 && status != 202 {
		return nil, fmt.Errorf("failed to fetch note value at index %d; status: %v", index, status)
	}

	val := &StoreValueResponse{}
	raw, _ := json.Marshal(resp)
	json.Unmarshal(raw, &val)

	return val, nil
}

// GetNullifierValue fetches the value in the nullifier store at the specified key
func GetNullifierValue(token, circuitID, key string) (*StoreValueResponse, error) {
	uri := fmt.Sprintf("circuits/%s/nullifiers/%s", circuitID, key)
	status, resp, err := InitPrivacyService(token).Get(uri, map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	if status != 200 && status != 202 {
		return nil, fmt.Errorf("failed to fetch note nullifier with key %s; status: %v", key, status)
	}

	val := &StoreValueResponse{}
	raw, _ := json.Marshal(resp)
	json.Unmarshal(raw, &val)

	return val, nil
}
