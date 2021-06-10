package baseline

import (
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/api/privacy"
)

const ProtocolMessageOpcodeBaseline = "BLINE"
const ProtocolMessageOpcodeJoin = "JOIN"
const ProtocolMessageOpcodeSync = "SYNC"

// BaselineRecord represents a link between an object in the internal system of record
// and the external baseline workflow context
type BaselineRecord struct {
	BaselineID *uuid.UUID `sql:"-" json:"baseline_id,omitempty"`
	ID         *string    `sql:"-" json:"id,omitempty"`
	Type       *string    `sql:"-" json:"type,omitempty"`
	Workflow   *Workflow  `sql:"-" json:"-"`
	WorkflowID *uuid.UUID `sql:"-" json:"identifier"`
}

// Config represents the proxy configuration
type Config struct {
	Counterparties           []*Participant    `sql:"-" json:"counterparties,omitempty"`
	Env                      map[string]string `sql:"-" json:"env,omitempty"`
	Errors                   []*api.Error      `sql:"-" json:"errors,omitempty"`
	NetworkID                *uuid.UUID        `sql:"-" json:"network_id,omitempty"`
	OrganizationAddress      *string           `sql:"-" json:"organization_address,omitempty"`
	OrganizationID           *uuid.UUID        `sql:"-" json:"organization_id,omitempty"`
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

// Message is a proxy-internal wrapper for protocol message handling
type Message struct {
	BaselineID      *uuid.UUID       `sql:"-" json:"baseline_id,omitempty"` // optional; when included, can be used to map outbound message just-in-time
	Errors          []*api.Error     `sql:"-" json:"errors,omitempty"`
	ID              *string          `sql:"-" json:"id,omitempty"`
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

// Workgroup is a baseline workgroup context
type Workgroup struct {
	ID           *uuid.UUID     `sql:"-" json:"id,omitempty"`
	Participants []*Participant `sql:"-" json:"participants"`
	Workflows    []*Workflow    `json:"workflows,omitempty"`

	PrivacyPolicy      interface{} `json:"privacy_policy"`      // outlines data visibility rules for each participant
	SecurityPolicy     interface{} `json:"security_policy"`     // consists of authentication and authorization rules for the workgroup participants
	TokenizationPolicy interface{} `json:"tokenization_policy"` // consists of policies governing tokenization of workflow outputs
}

// Workflow is a baseline workflow context
type Workflow struct {
	ID           *uuid.UUID     `sql:"-" json:"id,omitempty"`
	Participants []*Participant `sql:"-" json:"participants"`
	Shield       *string        `sql:"-" json:"shield,omitempty"`
	Worksteps    []*Workstep    `sql:"-" json:"worksteps,omitempty"`
}

// Workstep is a baseline workflow context
type Workstep struct {
	ID           *uuid.UUID       `sql:"-" json:"id,omitempty"`
	Circuit      *privacy.Circuit `sql:"-" json:"circuit,omitempty"`
	Participants []*Participant   `sql:"-" json:"participants"`
}
