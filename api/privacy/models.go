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
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/provide-go/api"
)

// Prover model
type Prover struct {
	*api.Model

	Name          *string `json:"name"`
	Description   *string `json:"description"`
	Identifier    *string `json:"identifier"`
	Provider      *string `json:"provider"`
	ProvingScheme *string `json:"proving_scheme"`
	Curve         *string `json:"curve"`
	Status        *string `json:"status"`

	NoteStoreID      *uuid.UUID `json:"note_store_id"`
	NullifierStoreID *uuid.UUID `json:"nullifier_store_id"`

	ProvingKeyID   *uuid.UUID `json:"proving_key_id"`
	VerifyingKeyID *uuid.UUID `json:"verifying_key_id"`

	Artifacts        map[string]interface{} `json:"artifacts,omitempty"`
	VerifierContract map[string]interface{} `json:"verifier_contract,omitempty"`
}

// StoreValueResponse model
type StoreValueResponse struct {
	Errors       []*api.Error           `json:"errors,omitempty"`
	Length       *int                   `json:"length,omitempty"`
	Root         *string                `json:"root,omitempty"`
	NullifierKey *string                `json:"nullifier_key,omitempty"`
	Value        *string                `json:"value"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
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
