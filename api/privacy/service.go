/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

// ListProvers lists the provers in the scope of the given bearer token
func ListProvers(token string, params map[string]interface{}) ([]*Prover, error) {
	status, resp, err := InitPrivacyService(token).Get("provers", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list provers; status: %v", status)
	}

	provers := make([]*Prover, 0)
	for _, item := range resp.([]interface{}) {
		prover := &Prover{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &prover)
		provers = append(provers, prover)
	}

	return provers, nil
}

// GetProverDetails fetches details for the given prover
func GetProverDetails(token, proverID string) (*Prover, error) {
	uri := fmt.Sprintf("provers/%s", proverID)
	status, resp, err := InitPrivacyService(token).Get(uri, map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch prover; status: %v", status)
	}

	prover := &Prover{}
	raw, _ := json.Marshal(resp)
	json.Unmarshal(raw, &prover)

	return prover, nil
}

// CreateProver creates a new prover in the registry
func CreateProver(token string, params map[string]interface{}) (*Prover, error) {
	status, resp, err := InitPrivacyService(token).Post("provers", params)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create prover; status: %v", status)
	}

	prover := &Prover{}
	raw, _ := json.Marshal(resp)
	json.Unmarshal(raw, &prover)

	return prover, nil
}

// Prove generates a proof using the given inputs for the named prover
func Prove(token, proverID string, params map[string]interface{}) (*ProveResponse, error) {
	uri := fmt.Sprintf("provers/%s/prove", proverID)
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

// Verify verifies the given inputs using the named prover
func Verify(token, proverID string, params map[string]interface{}) (*VerificationResponse, error) {
	uri := fmt.Sprintf("provers/%s/verify", proverID)
	status, resp, err := InitPrivacyService(token).Post(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 && status != 202 {
		return nil, fmt.Errorf("failed to verify prover inputs; status: %v", status)
	}

	verification := &VerificationResponse{}
	raw, _ := json.Marshal(resp)
	json.Unmarshal(raw, &verification)

	return verification, nil
}

// GetNoteValue fetches the value in the note store at a specified index
func GetNoteValue(token, proverID string, index uint64) (*StoreValueResponse, error) {
	uri := fmt.Sprintf("provers/%s/notes/%d", proverID, index)
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
func GetNullifierValue(token, proverID, key string) (*StoreValueResponse, error) {
	uri := fmt.Sprintf("provers/%s/nullifiers/%s", proverID, key)
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
