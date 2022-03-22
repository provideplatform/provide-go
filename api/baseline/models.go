package baseline

import (
	"encoding/json"
	"time"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/nchain"
	"github.com/provideplatform/provide-go/api/privacy"
	"github.com/provideplatform/provide-go/api/vault"
)

const ProtocolMessageOpcodeBaseline = "BLINE"
const ProtocolMessageOpcodeJoin = "JOIN"
const ProtocolMessageOpcodeSync = "SYNC"

// BaselineContext represents a collection of BaselineRecord instances in the context of a workflow
type BaselineContext struct {
	ID         *uuid.UUID        `sql:"-" json:"id,omitempty"`
	BaselineID *uuid.UUID        `sql:"-" json:"baseline_id,omitempty"`
	Records    []*BaselineRecord `sql:"-" json:"records,omitempty"`
	Workflow   *Workflow         `sql:"-" json:"-"`
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
	Models      []*MappingModel `json:"models"`
	Name        string          `json:"name"`
	Description *string         `json:"description"`
	Type        *string         `json:"type"`
}

// MappingField for mapping
type MappingField struct {
	DefaultValue interface{} `json:"default_value,omitempty"`
	IsPrimaryKey bool        `json:"is_primary_key"`
	Name         string      `json:"name"`
	Description  *string     `json:"description"`
	Type         string      `json:"type"`
}

// MappingModel consists of fields for mapping
type MappingModel struct {
	Description *string         `json:"description"`
	Fields      []*MappingField `json:"fields"`
	PrimaryKey  *string         `json:"primary_key"`
	Standard    *string         `json:"standard"`
	Type        *string         `json:"type"`
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
}

// Participant is a party to a baseline workgroup or workflow context
type Participant struct {
	Address           *string                `sql:"-" json:"address"`
	Metadata          map[string]interface{} `sql:"-" json:"metadata,omitempty"`
	APIEndpoint       *string                `sql:"-" json:"api_endpoint,omitempty"`
	MessagingEndpoint *string                `sql:"-" json:"messaging_endpoint,omitempty"`
	WebsocketEndpoint *string                `sql:"-" json:"websocket_endpoint,omitempty"`
}

// ProtocolMessage is a baseline protocol message
// see https://github.com/ethereum-oasis/baseline/blob/master/core/types/src/protocol.ts
type ProtocolMessage struct {
	BaselineID *uuid.UUID              `sql:"-" json:"baseline_id,omitempty"`
	Opcode     *string                 `sql:"-" json:"opcode,omitempty"`
	Sender     *string                 `sql:"-" json:"sender,omitempty"`
	Recipient  *string                 `sql:"-" json:"recipient,omitempty"`
	Shield     *string                 `sql:"-" json:"shield,omitempty"`
	Identifier *uuid.UUID              `sql:"-" json:"identifier,omitempty"`
	Signature  *string                 `sql:"-" json:"signature,omitempty"`
	Type       *string                 `sql:"-" json:"type,omitempty"`
	Payload    *ProtocolMessagePayload `sql:"-" json:"payload,omitempty"`
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

// SubjectAccount is a baseline BPI Subject Account per the specification
type SubjectAccount struct {
	api.ModelWithDID
	Credentials      *json.RawMessage        `json:"credentials,omitempty"`
	Metadata         *SubjectAccountMetadata `json:"metadata,omitempty"`
	RecoveryPolicy   *json.RawMessage        `gorm:"column:recoverypolicy" json:"recovery_policy,omitempty"`
	Role             *json.RawMessage        `json:"role,omitempty"`
	SecurityPolicies *json.RawMessage        `gorm:"column:securitypolicies" json:"security_policies,omitempty"`
	SubjectID        *string                 `json:"subject_id"`
	Type             *string                 `json:"type,omitempty"`
}

// SubjectAccountMetadata is `SubjectAccount` metadata specific to this BPI instance
type SubjectAccountMetadata struct {
	// Counterparties are the default counterparties
	Counterparties []*Participant `sql:"-" json:"counterparties,omitempty"`

	// NetworkID is the baseline network id
	NetworkID *string `json:"network_id,omitempty"`

	// OrganizationAddress is the baseline organization address
	OrganizationAddress *string `json:"organization_address,omitempty"`

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
	RegistryContract *nchain.CompiledArtifact `json:"-"`

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
}

// Workflow is a baseline workflow prototype
type Workflow struct {
	api.Model
	DeployedAt   *time.Time       `json:"deployed_at"`
	Metadata     *json.RawMessage `sql:"type:json not null" json:"metadata,omitempty"`
	Participants []*Participant   `sql:"-" json:"participants"`
	Shield       *string          `json:"shield,omitempty"`
	Status       *string          `json:"status"`
	Version      *string          `json:"version"`
	Worksteps    []*Workstep      `sql:"-" json:"worksteps,omitempty"`
}

// WorkflowInstance is a baseline workflow instance
type WorkflowInstance struct {
	Workflow
	WorkflowID *uuid.UUID          `json:"workflow_id,omitempty"` // references the workflow prototype identifier
	Worksteps  []*WorkstepInstance `sql:"-" json:"worksteps,omitempty"`
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
}

// WorkstepInstance is a baseline workstep instance
type WorkstepInstance struct {
	Workstep
	WorkstepID *uuid.UUID `json:"workstep_id,omitempty"` // references the workstep prototype identifier
}
