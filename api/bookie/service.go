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
