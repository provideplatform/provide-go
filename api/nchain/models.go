package nchain

import (
	"database/sql/driver"
	"encoding/json"
	"math/big"
	"net/url"
	"time"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/provide-go/api"
)

// Account contains the specific account user details
type Account struct {
	api.Model

	NetworkID      *uuid.UUID `json:"network_id,omitempty"`
	WalletID       *uuid.UUID `json:"wallet_id,omitempty"`
	ApplicationID  *uuid.UUID `json:"application_id,omitempty"`
	UserID         *uuid.UUID `json:"user_id,omitempty"`
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`

	VaultID *uuid.UUID `json:"vault_id,omitempty"`
	KeyID   *uuid.UUID `json:"key_id,omitempty"`

	Type *string `json:"type,omitempty"`

	HDDerivationPath *string `json:"hd_derivation_path,omitempty"` // i.e. m/44'/60'/0'/0
	PublicKey        *string `json:"public_key,omitempty"`
	PrivateKey       *string `json:"private_key,omitempty"`

	Address    string     `json:"address"`
	Balance    *big.Int   `json:"balance,omitempty"`
	AccessedAt *time.Time `json:"accessed_at,omitempty"`
}

// CompiledArtifact represents compiled sourcecode
type CompiledArtifact struct {
	Name        string          `json:"name"`
	ABI         []interface{}   `json:"abi"`
	Assembly    interface{}     `json:"assembly,omitempty"`
	Bytecode    string          `json:"bytecode"`
	Deps        []interface{}   `json:"deps,omitempty"`
	Opcodes     string          `json:"opcodes,omitempty"`
	Raw         json.RawMessage `json:"raw"`
	Source      *string         `json:"source"`
	Fingerprint *string         `json:"fingerprint"`
}

// Connector instances represent a logical connection to IPFS or other decentralized filesystem;
// in the future it may represent a logical connection to services of other types
type Connector struct {
	api.Model

	ApplicationID  *uuid.UUID       `json:"application_id"`
	NetworkID      uuid.UUID        `json:"network_id"`
	OrganizationID *uuid.UUID       `json:"organization_id"`
	Name           *string          `json:"name"`
	Type           *string          `json:"type"`
	Status         *string          `json:"status"`
	Description    *string          `json:"description"`
	Config         *json.RawMessage `json:"config,omitempty"`
	IsVirtual      bool             `json:"is_virtual,omitempty"`
	AccessedAt     *time.Time       `json:"accessed_at,omitempty"`

	Details *ConnectorDetails `json:"details,omitempty"`
}

// ConnectorDetails is a generic representation for a type-specific enrichment of a described connector;
// the details object may have complexity of its own, such as paginated subresults
type ConnectorDetails struct {
	Page *int64      `json:"page,omitempty"`
	RPP  *int64      `json:"rpp,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

// Contract instances must be associated with an application identifier.
type Contract struct {
	api.Model

	ApplicationID *uuid.UUID `json:"application_id"`
	NetworkID     uuid.UUID  `json:"network_id"`
	ContractID    *uuid.UUID `json:"contract_id"`    // id of the contract which created the contract (or null)
	TransactionID *uuid.UUID `json:"transaction_id"` // id of the transaction which deployed the contract (or null)

	Name         *string          `json:"name"`
	Address      *string          `json:"address"`
	Type         *string          `json:"type"`
	Params       *json.RawMessage `json:"params,omitempty"`
	AccessedAt   *time.Time       `json:"accessed_at"`
	PubsubPrefix *string          `json:"pubsub_prefix,omitempty"`
}

// EthereumTxTraceResponse is returned upon successful contract execution
type EthereumTxTraceResponse struct {
	Result []struct {
		Action struct {
			CallType *string `json:"callType"`
			From     *string `json:"from"`
			Gas      *string `json:"gas"`
			Init     *string `json:"init"`
			Input    *string `json:"input"`
			To       *string `json:"to"`
			Value    *string `json:"value"`
		} `json:"action"`
		BlockHash   *string `json:"blockHash"`
		BlockNumber int     `json:"blockNumber"`
		Result      struct {
			Address *string `json:"address"`
			Code    *string `json:"code"`
			GasUsed *string `json:"gasUsed"`
			Output  *string `json:"output"`
		} `json:"result"`
		Error               *string       `json:"error"`
		Subtraces           int           `json:"subtraces"`
		TraceAddress        []interface{} `json:"traceAddress"`
		TransactionHash     *string       `json:"transactionHash"`
		TransactionPosition int           `json:"transactionPosition"`
		Type                *string       `json:"type"`
	} `json:"result"`
}

// ContractExecutionResponse is a response from the contract execution call
type ContractExecutionResponse struct {
	Confidence float64     `json:"confidence"`
	Reference  *string     `json:"ref"`
	Response   interface{} `json:"response,omitempty"`
}

// Network contains the specific Ethereum network details (mainnet, etc.)
type Network struct {
	api.Model

	ApplicationID *uuid.UUID       `json:"application_id,omitempty"`
	UserID        *uuid.UUID       `json:"user_id,omitempty"`
	Name          *string          `json:"name"`
	Description   *string          `json:"description"`
	Enabled       *bool            `json:"enabled"`
	ChainID       *string          `json:"chain_id"`             // protocol-specific chain id
	NetworkID     *uuid.UUID       `json:"network_id,omitempty"` // network id used as the parent
	Config        *json.RawMessage `json:"config,omitempty"`
}

// NetworkLogEvent is a network-agnostic log event
type NetworkLog struct {
	Address   *string `json:"address,omitempty"`
	Block     uint64  `json:"block,omitempty"`
	BlockHash *string `json:"blockhash,omitempty"`
	Data      *string `json:"data,omitempty"`
	// Index           *big.Int               `json:"log_index,omitempty"`
	NetworkID       *string                `json:"network_id,omitempty"`
	Timestamp       uint64                 `json:"timestamp,omitempty"`
	Topics          []*string              `json:"topics,omitempty"`
	TransactionHash *string                `json:"transaction_hash,omitempty"`
	Type            *string                `json:"type,omitempty"`
	Params          map[string]interface{} `json:"params,omitempty"`
}

// NetworkStatus provides network-agnostic status
type NetworkStatus struct {
	Block           uint64                 `json:"block,omitempty"`            // current block
	ChainID         *string                `json:"chain_id,omitempty"`         // the chain id
	Height          *uint64                `json:"height,omitempty"`           // total height of the blockchain; null after syncing completed
	LastBlockAt     *uint64                `json:"last_block_at,omitempty"`    // unix timestamp of the last block; i.e., when the last block was collated
	PeerCount       uint64                 `json:"peer_count,omitempty"`       // number of peers connected to the JSON-RPC client
	ProtocolVersion *string                `json:"protocol_version,omitempty"` // protocol version
	State           *string                `json:"state,omitempty"`            // i.e., syncing, synced, etc
	Syncing         bool                   `json:"syncing,omitempty"`          // when true, the network is in the process of syncing the ledger; available functionaltiy will be network-specific
	Meta            map[string]interface{} `json:"meta,omitempty"`             // network-specific metadata
}

// Oracle instances are smart contracts whose terms are fulfilled
// writing data from a configured feed onto the blockchain
type Oracle struct {
	api.Model

	ApplicationID *uuid.UUID `json:"application_id"`
	NetworkID     uuid.UUID  `json:"network_id"`
	ContractID    uuid.UUID  `json:"contract_id"`

	Name          *string          `json:"name"`
	FeedURL       *url.URL         `json:"feed_url"`
	Params        *json.RawMessage `json:"params"`
	AttachmentIds []*uuid.UUID     `json:"attachment_ids"`
}

// Token contract
type Token struct {
	api.Model

	ApplicationID  *uuid.UUID `json:"application_id"`
	NetworkID      uuid.UUID  `json:"network_id"`
	ContractID     *uuid.UUID `json:"contract_id"`
	SaleContractID *uuid.UUID `json:"sale_contract_id"`

	Name        *string    `json:"name"`
	Symbol      *string    `json:"symbol"`
	Decimals    uint64     `json:"decimals"`
	Address     *string    `json:"address"`      // network-specific token contract address
	SaleAddress *string    `json:"sale_address"` // non-null if token sale contract is specified
	AccessedAt  *time.Time `json:"accessed_at"`
}

// Transaction instances are associated with a signing wallet and exactly one matching instance
// of either an a) application identifier or b) user identifier.
type Transaction struct {
	api.Model
	NetworkID uuid.UUID `json:"network_id,omitempty"`

	// Application or user id, if populated, is the entity for which the transaction was custodially signed and broadcast
	ApplicationID *uuid.UUID `json:"application_id,omitempty"`
	UserID        *uuid.UUID `json:"user_id,omitempty"`

	// Account or HD wallet which custodially signed the transaction; when an HD wallet is used, if no HD derivation path is provided,
	// the most recently derived non-zero account is used to sign
	AccountID *uuid.UUID `json:"account_id,omitempty"`
	WalletID  *uuid.UUID `json:"wallet_id,omitempty"`
	Path      *string    `json:"hd_derivation_path,omitempty"`

	// Network-agnostic tx fields
	Signer      *string          `json:"signer,omitempty"`
	To          *string          `json:"to"`
	Value       *TxValue         `json:"value"`
	Data        *string          `json:"data"`
	Hash        *string          `json:"hash"`
	Status      *string          `json:"status"`
	Params      *json.RawMessage `json:"params,omitempty"`
	Ref         *string          `json:"ref"`
	Description *string          `json:"description"`

	// Ephemeral fields for managing the tx/rx and tracing lifecycles
	Traces interface{} `json:"traces,omitempty"`

	// Transaction metadata/instrumentation
	Block          *uint64    `json:"block"`
	BlockTimestamp *time.Time `json:"block_timestamp,omitempty"` // timestamp when the tx was finalized on-chain, according to its tx receipt
	BroadcastAt    *time.Time `json:"broadcast_at,omitempty"`    // timestamp when the tx was broadcast to the network
	FinalizedAt    *time.Time `json:"finalized_at,omitempty"`    // timestamp when the tx was finalized on-platform
	PublishedAt    *time.Time `json:"published_at,omitempty"`    // timestamp when the tx was published to NATS cluster
	QueueLatency   *uint64    `json:"queue_latency,omitempty"`   // broadcast_at - published_at (in millis) -- the amount of time between when a message is enqueued to the NATS broker and when it is broadcast to the network
	NetworkLatency *uint64    `json:"network_latency,omitempty"` // finalized_at - broadcast_at (in millis) -- the amount of time between when a message is broadcast to the network and when it is finalized on-chain
	E2ELatency     *uint64    `json:"e2e_latency,omitempty"`     // finalized_at - published_at (in millis) -- the amount of time between when a message is published to the NATS broker and when it is finalized on-chain
}

// RPCResponse represents a generic json-rpc response
type RPCResponse struct {
	ID      interface{}            `json:"id"`
	Jsonrpc string                 `json:"jsonrpc"`
	Result  map[string]interface{} `json:"result"`
}

// TxValue provides JSON marshaling and gorm driver support for wrapping/unwrapping big.Int
type TxValue struct {
	value *big.Int
}

// NewTxValue is a convenience method to return a TxValue
func NewTxValue(val int64) *TxValue {
	return &TxValue{value: big.NewInt(val)}
}

// BigInt returns the value represented as big.Int
func (v *TxValue) BigInt() *big.Int {
	return v.value
}

// MarshalJSON marshals the tx value to bytes
func (v *TxValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

// UnmarshalJSON sets the tx value big.Int from its string representation
func (v *TxValue) UnmarshalJSON(data []byte) error {
	v.value = new(big.Int)
	v.value.SetString(string(data), 10)
	return nil
}

// Value returns the underlying big.Int as a string for use by the gorm driver (psql)
func (v *TxValue) Value() (driver.Value, error) {
	return v.value.String(), nil
}

// Scan reads the persisted value using the gorm driver and marshals it into a TxValue
func (v *TxValue) Scan(val interface{}) error {
	v.value = new(big.Int)
	if str, ok := val.(string); ok {
		v.value.SetString(str, 10)
	}
	return nil
}

// Wallet contains the specific wallet details
type Wallet struct {
	api.Model

	WalletID       *uuid.UUID `json:"wallet_id,omitempty"`
	ApplicationID  *uuid.UUID `json:"application_id,omitempty"`
	UserID         *uuid.UUID `json:"user_id,omitempty"`
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`

	VaultID *uuid.UUID `json:"vault_id,omitempty"`
	KeyID   *uuid.UUID `json:"key_id,omitempty"`

	Path     *string `json:"path,omitempty"`
	Purpose  *int    `json:"purpose,omitempty"`
	Mnemonic *string `json:"mnemonic,omitempty"`

	PublicKey  *string `json:"public_key,omitempty"`
	PrivateKey *string `json:"private_key,omitempty"`
}
