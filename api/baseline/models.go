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

package baseline

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/nchain"
	"github.com/provideplatform/provide-go/api/privacy"
	"github.com/provideplatform/provide-go/api/vault"
	"github.com/provideplatform/provide-go/common"
)

const ProtocolMessageOpcodeBaseline = "BLINE"
const ProtocolMessageOpcodeJoin = "JOIN"
const ProtocolMessageOpcodeSync = "SYNC"

// BaselineContext represents a collection of BaselineRecord instances in the context of a workflow
type BaselineContext struct {
	ID         *uuid.UUID        `sql:"-" json:"id,omitempty"`
	BaselineID *uuid.UUID        `sql:"-" json:"baseline_id,omitempty"`
	Records    []*BaselineRecord `sql:"-" json:"records,omitempty"`
	Workflow   *WorkflowInstance `sql:"-" json:"-"`
	WorkflowID *uuid.UUID        `sql:"-" json:"workflow_id"`
}

// BaselineRecord represents a link between an object in the internal system of record
// and the external BaselineContext
type BaselineRecord struct {
	ID         *string          `sql:"-" json:"id,omitempty"`
	BaselineID *uuid.UUID       `sql:"-" json:"baseline_id,omitempty"`
	Context    *BaselineContext `sql:"-" json:"-"`
	ContextID  *uuid.UUID       `sql:"-" json:"context_id"`
	Type       *string          `sql:"-" json:"type"`
}

// Config represents the instance configuration
type Config struct {
	Counterparties           []*Participant    `sql:"-" json:"counterparties,omitempty"`
	Env                      map[string]string `sql:"-" json:"env,omitempty"`
	Errors                   []*api.Error      `sql:"-" json:"errors,omitempty"`
	NetworkID                *uuid.UUID        `sql:"-" json:"network_id,omitempty"`
	OrganizationAddress      *string           `sql:"-" json:"organization_address,omitempty"`
	OrganizationID           *uuid.UUID        `sql:"-" json:"organization_id,omitempty"`
	WorkgroupID              *uuid.UUID        `sql:"-" json:"workgroup_id,omitempty"`
	OrganizationRefreshToken *string           `sql:"-" json:"organization_refresh_token,omitempty"`
	RegistryContractAddress  *string           `sql:"-" json:"registry_contract_address,omitempty"`
}

// IssueVerifiableCredentialRequest represents a request to issue a verifiable credential
type IssueVerifiableCredentialRequest struct {
	Address        *string    `json:"address,omitempty"`
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`
	PublicKey      *string    `json:"public_key,omitempty"`
	Signature      *string    `json:"signature"`
}

// IssueVerifiableCredentialResponse represents a response to a VC issuance request
type IssueVerifiableCredentialResponse struct {
	VC *string `json:"credential"`
}

// Mapping for arbitrary model transformations
type Mapping struct {
	api.Model
	Models      []*MappingModel `json:"models"`
	Name        string          `json:"name"`
	Description *string         `json:"description"`
	Type        *string         `json:"type"`

	OrganizationID *uuid.UUID `json:"organization_id"`
	Ref            *string    `json:"ref,omitempty"`
	RefMappingID   *uuid.UUID `json:"ref_mapping_id"`
	Version        *string    `json:"version"`
	WorkgroupID    *uuid.UUID `json:"workgroup_id"`
}

// MappingModel consists of fields for mapping
type MappingModel struct {
	api.Model
	Description *string `json:"description"`
	PrimaryKey  *string `json:"primary_key"`
	Standard    *string `json:"standard"`
	Type        *string `json:"type"`

	MappingID  uuid.UUID       `json:"mapping_id"`
	RefModelID *uuid.UUID      `json:"ref_model_id"`
	Fields     []*MappingField `sql:"-" json:"fields"`
}

// MappingField for mapping
type MappingField struct {
	api.Model
	DefaultValue interface{} `json:"default_value,omitempty"`
	IsPrimaryKey bool        `json:"is_primary_key"`
	Name         string      `json:"name"`
	Description  *string     `json:"description"`
	Type         string      `json:"type"`

	MappingModelID uuid.UUID  `json:"mapping_model_id"` // gorm: "column:mappingmodel_id"
	RefFieldID     *uuid.UUID `json:"ref_field_id"`
}

// Message is a proxy-internal wrapper for protocol message handling
type Message struct {
	ID              *string          `sql:"-" json:"id,omitempty"`
	BaselineID      *uuid.UUID       `sql:"-" json:"baseline_id,omitempty"` // optional; when included, can be used to map outbound message just-in-time
	Errors          []*api.Error     `sql:"-" json:"errors,omitempty"`
	MessageID       *string          `sql:"-" json:"message_id,omitempty"`
	Payload         interface{}      `sql:"-" json:"payload,omitempty"`
	ProtocolMessage *ProtocolMessage `sql:"-" json:"protocol_message,omitempty"`
	Recipients      []*Participant   `sql:"-" json:"recipients"`
	Status          *string          `sql:"-" json:"status,omitempty"`
	Type            *string          `sql:"-" json:"type,omitempty"`

	// HACK -- convenience ptr ... for access during baselineOutbound()
	subjectAccount *SubjectAccount `sql:"-" json:"-"`
	token          *string         `sql:"-" json:"-"`
}

// Participant is a party to a baseline workgroup or workflow context
type Participant struct {
	Metadata          map[string]interface{} `sql:"-" json:"metadata,omitempty"`
	BPIEndpoint       *string                `sql:"-" json:"bpi_endpoint,omitempty"`
	MessagingEndpoint *string                `sql:"-" json:"messaging_endpoint,omitempty"`
	WebsocketEndpoint *string                `sql:"-" json:"websocket_endpoint,omitempty"`

	Address    *string      `json:"address"` // gorm:"column:participant"
	Workgroups []*Workgroup `sql:"-" json:"workgroups,omitempty"`
	Workflows  []*Workflow  `sql:"-" json:"workflows,omitempty"`
	Worksteps  []*Workstep  `sql:"-" json:"worksteps,omitempty"`
}

// ProtocolMessage is a baseline protocol message
// see https://github.com/ethereum-oasis/baseline/blob/master/core/types/src/protocol.ts
type ProtocolMessage struct {
	BaselineID *uuid.UUID              `sql:"-" json:"baseline_id,omitempty"`
	Opcode     *string                 `sql:"-" json:"opcode,omitempty"`
	Sender     *string                 `sql:"-" json:"sender,omitempty"`
	Recipient  *string                 `sql:"-" json:"recipient,omitempty"`
	Shield     *string                 `sql:"-" json:"shield,omitempty"`
	Signature  *string                 `sql:"-" json:"signature,omitempty"`
	Type       *string                 `sql:"-" json:"type,omitempty"`
	Payload    *ProtocolMessagePayload `sql:"-" json:"payload,omitempty"`

	WorkgroupID *uuid.UUID `sql:"-" json:"workgroup_id,omitempty"`
	WorkflowID  *uuid.UUID `sql:"-" json:"workgroup_id,omitempty"`
	WorkstepID  *uuid.UUID `sql:"-" json:"workstep_id,omitempty"`

	// HACK -- convenience ptr ... for access during baselineInbound()
	subjectAccount *SubjectAccount `sql:"-" json:"-"`
	token          *string         `sql:"-" json:"-"`
}

// ProtocolMessagePayload is a baseline protocol message payload
type ProtocolMessagePayload struct {
	Object  map[string]interface{} `sql:"-" json:"object,omitempty"`
	Proof   *string                `sql:"-" json:"proof,omitempty"`
	Type    *string                `sql:"-" json:"type,omitempty"`
	Witness interface{}            `sql:"-" json:"witness,omitempty"`
}

// PublicWorkgroupInvitationRequest represents parameters for an anonymous request to a public workgroup
type PublicWorkgroupInvitationRequest struct {
	Email            *string `json:"email"`
	FirstName        *string `json:"first_name"`
	LastName         *string `json:"last_name"`
	OrganizationName *string `json:"organization_name"`
}

// BaselineClaims represent JWT claims encoded within a generic verifiable credential for use with the baseline protocol
type BaselineClaims struct {
	jwt.MapClaims
	RegistryContractAddress *string `json:"registry_contract_address"`
	WorkgroupID             *string `json:"workgroup_id"`
}

// BaselineInviteClaims represent JWT claims encoded within an verifiable credential representing an invitation
type BaselineInviteClaims struct {
	BaselineClaims
	InvitorOrganizationAddress *string `json:"invitor_organization_address"`
	InvitorSubjectAccountID    *string `json:"invitor_subject_account_id"`
}

// InviteClaims represent JWT invitation claims
type InviteClaims struct {
	jwt.StandardClaims
	NATS *NATSClaims `json:"nats"`
	PRVD *PRVDClaims `json:"prvd"`
}

// NATSClaims represent JWT invitation nats claims
type NATSClaims struct {
	Permissions *PermissionsClaims `json:"permissions"`
}

// NATSClaims represent JWT invitation nats permissions claims
type PermissionsClaims struct {
	Publish   *PublishClaims   `json:"publish"`
	Subscribe *SubscribeClaims `json:"subscribe"`
}

// PublishClaims represent JWT invitation nats publish permissions claims
type PublishClaims struct {
	Allow []*string `json:"allow"`
}

// SubscribeClaims represent JWT invitation nats subscribe permissions claims
type SubscribeClaims struct {
	Allow []*string `json:"allow"`
}

// PRVDClaims represent JWT invitation PRVD claims
type PRVDClaims struct {
	Data        *DataClaims `json:"data"`
	Permissions uint32      `json:"permissions"`
}

// PRVDClaims represent JWT invitation PRVD data claims
type DataClaims struct {
	ApplicationID    *uuid.UUID   `json:"application_id"`
	Email            *string      `json:"email"`
	FirstName        *string      `json:"first_name"`
	InvitorID        *uuid.UUID   `json:"invitor_id"`
	InvitorName      *string      `json:"invitor_name"`
	LastName         *string      `json:"last_name"`
	OrganizationID   *uuid.UUID   `json:"organization_id"`
	OrganizationName *string      `json:"organization_name"`
	Params           *ClaimParams `json:"params"`
	UserID           *uuid.UUID   `json:"user_id"`
}

// PRVDClaims represent JWT invitation PRVD data claim params
type ClaimParams struct {
	AuthorizedBearerToken    *string    `json:"authorized_bearer_token,omitempty"`
	IsOrganizationInvite     bool       `json:"is_organization_invite,omitempty"`
	IsOrganizationUserInvite bool       `json:"is_organization_user_invite,omitempty"`
	OperatorSeparationDegree uint32     `json:"operator_separation_degree"`
	Workgroup                *Workgroup `json:"workgroup"`
}

// SubjectAccount is a baseline BPI Subject Account per the specification
type SubjectAccount struct {
	api.ModelWithDID
	SubjectID *string    `json:"subject_id"`
	Type      *string    `json:"type,omitempty"`
	VaultID   *uuid.UUID `json:"vault_id"`

	Credentials         *json.RawMessage `sql:"-" json:"credentials,omitempty"`
	CredentialsSecretID *uuid.UUID       `json:"credentials_secret_id,omitempty"`

	Metadata         *SubjectAccountMetadata `sql:"-" json:"metadata,omitempty"`
	MetadataSecretID *uuid.UUID              `json:"metadata_secret_id,omitempty"`

	RecoveryPolicy         *json.RawMessage `sql:"-" json:"recovery_policy,omitempty"`
	RecoveryPolicySecretID *uuid.UUID       `json:"recovery_policy_secret_id,omitempty"`

	Role         *json.RawMessage `sql:"-" json:"role,omitempty"`
	RoleSecretID *uuid.UUID       `json:"role_secret_id,omitempty"`

	SecurityPolicies         *json.RawMessage `sql:"-" json:"security_policies,omitempty"`
	SecurityPoliciesSecretID *uuid.UUID       `json:"security_policies_secret_id,omitempty"`

	RefreshToken    *string `json:"-"` // encrypted, hex-encoded refresh token for the BPI subject account
	refreshTokenRaw *string `sql:"-" json:"-"`
}

// SubjectAccountMetadata is `SubjectAccount` metadata specific to this BPI instance
type SubjectAccountMetadata struct {
	// Counterparties are the default counterparties
	Counterparties []*Participant `sql:"-" json:"counterparties,omitempty"`

	// NetworkID is the baseline network id
	NetworkID *string `json:"network_id,omitempty"`

	// OrganizationAddress is the baseline organization address
	OrganizationAddress *string `json:"organization_address,omitempty"`

	// OrganizationDomain is the baseline organization domain
	OrganizationDomain *string `json:"organization_domain,omitempty"`

	// OrganizationID is the id of the org
	OrganizationID *string `json:"organization_id,omitempty"`

	// OrganizationMessagingEndpoint is the public organziation messaging endpoint
	OrganizationMessagingEndpoint *string `json:"organization_messaging_endpoint,omitempty"`

	// OrganizationProxyEndpoint is the configured endpoint for the baseline proxy REST API
	OrganizationProxyEndpoint *string `json:"organization_proxy_endpoint,omitempty"`

	// OrganizationRefreshToken is the refresh token for the org
	OrganizationRefreshToken *string `json:"organization_refresh_token,omitempty"`

	// OrganizationWebsocketEndpoint is the configured endpoint for the baseline websocket
	OrganizationWebsocketEndpoint *string `json:"organization_websocket_endpoint,omitempty"`

	// RegistryContractAddress is a contract address
	RegistryContractAddress *string `json:"registry_contract_address,omitempty"`

	// RegistryContract is a compiled contract artifact
	RegistryContract *nchain.CompiledArtifact `sql:"-" json:"-"`

	// SOR contains one or more systems of record configurations
	SOR map[string]interface{} `json:"sor,omitempty"`

	// WorkgroupID is the id of the workgroup
	WorkgroupID *string `json:"workgroup_id,omitempty"`

	// Vault is the vault instance
	Vault *vault.Vault `sql:"-" json:"-"`
}

// Workgroup is a baseline workgroup context
type Workgroup struct {
	api.Model
	Participants       []*Participant `sql:"-" json:"participants,omitempty"`
	Shield             *string        `json:"shield,omitempty"`
	Workflows          []*Workflow    `sql:"-" json:"workflows,omitempty"`
	PrivacyPolicy      interface{}    `json:"privacy_policy"`      // outlines data visibility rules for each participant
	SecurityPolicy     interface{}    `json:"security_policy"`     // consists of authentication and authorization rules for the workgroup participants
	TokenizationPolicy interface{}    `json:"tokenization_policy"` // consists of policies governing tokenization of workflow outputs

	Name           *string     `json:"name"`
	Description    *string     `json:"description"`
	Config         interface{} `sql:"-" json:"config"`
	NetworkID      *uuid.UUID  `sql:"-" json:"network_id"`
	OrganizationID *uuid.UUID  `json:"-"`
}

// Workflow is a baseline workflow prototype
type Workflow struct {
	api.Model
	DeployedAt *time.Time       `json:"deployed_at"`
	Metadata   *json.RawMessage `sql:"type:json not null" json:"metadata,omitempty"`
	Shield     *string          `json:"shield,omitempty"`
	Status     *string          `json:"status"`
	Version    *string          `json:"version"`

	Name           *string        `json:"name"`
	Description    *string        `json:"description"`
	UpdatedAt      *time.Time     `json:"updated_at"`
	Participants   []*Participant `sql:"-" json:"participants,omitempty"`
	WorkgroupID    *uuid.UUID     `json:"workgroup_id"`
	WorkflowID     *uuid.UUID     `json:"workflow_id"` // when nil, indicates the workflow is a prototype (not an instance)
	Worksteps      []*Workstep    `json:"worksteps,omitempty"`
	WorkstepsCount int            `json:"worksteps_count,omitempty"`
}

// WorkflowVersion is a version of a workflow referenced by the initial workflow id
type WorkflowVersion struct {
	InitialWorkflowID uuid.UUID `json:"initial_workflow_id"`
	WorkflowID        uuid.UUID `json:"workflow_id"`
	Version           string    `json:"version"`
}

// WorkflowInstance is a baseline workflow instance
type WorkflowInstance struct {
	Workflow
	WorkflowID *uuid.UUID          `json:"workflow_id,omitempty"` // references the workflow prototype identifier
	Worksteps  []*WorkstepInstance `json:"worksteps,omitempty"`
}

// Workstep is a baseline workstep context
type Workstep struct {
	api.Model
	Name            *string          `json:"name"`
	Cardinality     int              `json:"cardinality"`
	DeployedAt      *time.Time       `json:"deployed_at"`
	Metadata        *json.RawMessage `sql:"type:json not null" json:"metadata,omitempty"`
	Prover          *privacy.Prover  `json:"prover,omitempty"`
	ProverID        *uuid.UUID       `json:"prover_id"`
	Participants    []*Participant   `sql:"-" json:"participants,omitempty"`
	RequireFinality bool             `json:"require_finality"`
	Shield          *string          `json:"shield,omitempty"`
	Status          *string          `json:"status"`
	WorkflowID      *uuid.UUID       `json:"workflow_id,omitempty"`

	Description *string    `json:"description"`
	WorkstepID  *uuid.UUID `json:"workstep_id"` // when nil, indicates the workstep is a prototype (not an instance)

	userInputCardinality bool `json:"-"`
}

// WorkstepInstance is a baseline workstep instance
type WorkstepInstance struct {
	Workstep
	WorkstepID *uuid.UUID `json:"workstep_id,omitempty"` // references the workstep prototype identifier
}

// SubjectAccountIDFactory returns H(organization_id, workgroup_id)
func SubjectAccountIDFactory(organizationID, workgroupID string) string {
	return common.SHA256(fmt.Sprintf("%s.%s", organizationID, workgroupID))
}

// WorkgroupDashboardAPIResponse is a general response containing data related to the current workgroup and organization context
type WorkgroupDashboardAPIResponse struct {
	Activity     []*ActivityAPIResponseItem `json:"activity"`
	Analytics    *AnalyticsAPIResponse      `json:"analytics"`
	Participants *ParticipantsAPIResponse   `json:"participants"`
	Workflows    *WorkflowsAPIResponse      `json:"workflows"`
}

// ActivityAPIResponseItem is a single activity item for inclusion in the `WorkgroupDashboardAPIResponse`
type ActivityAPIResponseItem struct {
	Metadata  *json.RawMessage `json:"metadata,omitempty"`
	Subtitle  *string          `json:"subtitle"`
	Timestamp *time.Time       `json:"timestamp"`
	Title     *string          `json:"title"`

	WorkflowID *uuid.UUID `json:"workflow_id"`
	WorkstepID *uuid.UUID `json:"workstep_id"`
}

// AnalyticsAPIResponse is the analytics item for inclusion in the `WorkgroupDashboardAPIResponse`
type AnalyticsAPIResponse struct {
	Metadata *json.RawMessage          `json:"metadata,omitempty"`
	Tree     *TreeAnalyticsAPIResponse `json:"tree"`
}

// TreeAnalyticsAPIResponse is the tree analtics time-series item for inclusion in the `AnalyticsAPIResponse`
type TreeAnalyticsAPIResponse struct {
	StartAt *time.Time `json:"start_at"`
	EndAt   *time.Time `json:"end_at"`

	Items    []*TreeAnalyticsAPIResponseItem `json:"items"`
	Metadata *json.RawMessage                `json:"metadata,omitempty"`
}

// TreeAnalyticsAPIResponseItem is the tree analtics time-series item for inclusion in the `AnalyticsAPIResponse`
type TreeAnalyticsAPIResponseItem struct {
	Date     *time.Time       `json:"date"`
	Metadata *json.RawMessage `json:"metadata,omitempty"`
	Size     uint64           `json:"size"` // in bytes
	Subtitle *string          `json:"subtitle"`
	Title    *string          `json:"title"`
}

// ParticipantsAPIResponse is the participants item for inclusion in the `WorkgroupDashboardAPIResponse`
type ParticipantsAPIResponse struct {
	ActionItemsCount   *uint64 `json:"action_items_count"`
	UsersCount         *uint64 `json:"users_count"`
	OrganizationsCount *uint64 `json:"organizations_count"`
}

// WorkflowsAPIResponse is the workflows item for inclusion in the `WorkgroupDashboardAPIResponse`
type WorkflowsAPIResponse struct {
	DelayedCount   *uint64 `json:"delayed_count"`
	DraftCount     *uint64 `json:"draft_count"`
	PublishedCount *uint64 `json:"published_count"`
}

// Schema is a schema from a connected sap system of record to create a mapping from
type Schema struct {
	Description *string       `json:"description"`
	Fields      []interface{} `json:"fields,omitempty"`
	Name        *string       `json:"name"`
	Type        *string       `json:"type"`
}

// System is a persistent representation and instance of a functional
// `middleware.System` implementation that uses a vault secret to
// securely store the configuration
type System struct {
	api.Model

	Name           *string    `sql:"not null" json:"name"`
	Description    *string    `json:"description"`
	Type           *string    `sql:"not null" json:"type"`
	OrganizationID *uuid.UUID `sql:"not null" json:"organization_id"`
	WorkgroupID    *uuid.UUID `sql:"not null" json:"workgroup_id"`

	Auth        *SystemAuth       `sql:"-" json:"auth,omitempty"`
	EndpointURL *string           `sql:"-" json:"endpoint_url"`
	Middleware  *SystemMiddleware `sql:"-" json:"middleware,omitempty"`

	VaultID  *uuid.UUID `sql:"not null" json:"-"`
	SecretID *uuid.UUID `sql:"not null" json:"-"`
}

// SystemAuth defines authn/authz params
type SystemAuth struct {
	Method   *string `json:"name"`
	Username *string `json:"username"`
	Password *string `json:"password,omitempty"`

	RequireClientCredentials bool    `json:"require_client_credentials"`
	ClientID                 *string `json:"client_id"`
	ClientSecret             *string `json:"client_secret"`
}

// SystemMiddleware defines middleware for inbound and outbound middleware
type SystemMiddlewarePolicy struct {
	Auth *SystemAuth `json:"auth"`
	Name *string     `json:"name"`
	URL  *string     `json:"url"`
}

// SystemMiddleware defines middleware for inbound and outbound middleware
type SystemMiddleware struct {
	Inbound  *SystemMiddlewarePolicy `json:"inbound,omitempty"`
	Outbound *SystemMiddlewarePolicy `json:"outbound,omitempty"`
}
