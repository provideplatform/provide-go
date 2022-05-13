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
	"math/big"

	uuid "github.com/kthomas/go.uuid"

	"github.com/provideplatform/provide-go/api"
)

// BillingAccount instances represent a virtual account with which payment methods can be
// associated (i.e., for charging customers); currently this is a singleton-per-user
type BillingAccount struct {
	api.Model

	ApplicationID  uuid.UUID `json:"application_id,omitempty"`
	OrganizationID uuid.UUID `json:"organization_id,omitempty"`
	UserID         uuid.UUID `json:"user_id,omitempty"`

	Nickname             *string    `json:"nickname"`
	KYCProvider          *string    `json:"kyc_provider,omitempty"`
	KYCApplicationID     *uuid.UUID `json:"kyc_application_id,omitempty"`
	MoneyServiceProvider *string    `json:"money_service_provider,omitempty"`
	Identifier           *string    `json:"identifier,omitempty"`
	Address              *string    `json:"address,omitempty"`
	Verified             bool       `json:"verified,omitempty"`
}

// PaymentMethod represents a tokenized or virtual means by which value can be transferred
type PaymentMethod struct {
	api.Model

	ApplicationID  uuid.UUID `json:"application_id,omitempty"`
	OrganizationID uuid.UUID `json:"organization_id,omitempty"`
	UserID         uuid.UUID `json:"user_id,omitempty"`

	Nickname *string          `json:"nickname"`
	Brand    *string          `json:"brand,omitempty"`
	ExpMonth *uint8           `json:"exp_month,omitempty"`
	ExpYear  *uint16          `json:"exp_year,omitempty"`
	Last4    *string          `json:"last4,omitempty"`
	Metadata *json.RawMessage `json:"metadata,omitempty"`
}

// Payment defines a payment request
type Payment struct {
	api.Model

	NetworkID uuid.UUID `json:"network_id,omitempty"`

	ApplicationID  uuid.UUID `json:"application_id,omitempty"`
	OrganizationID uuid.UUID `json:"organization_id,omitempty"`
	UserID         uuid.UUID `json:"user_id,omitempty"`

	Address     *string                `json:"address,omitempty"`
	Description *string                `json:"description"`
	Status      *string                `json:"status"`
	Type        *string                `json:"type"`
	Params      map[string]interface{} `json:"params"`
	Provider    *string                `json:"provider"`
	Value       *big.Int               `json:"value"`
}
