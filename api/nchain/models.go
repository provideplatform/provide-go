package nchain

import (
	"encoding/json"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	uuid "github.com/kthomas/go.uuid"
	"github.com/tyler-smith/go-bip32"
)

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

// TxReceipt is generalized transaction receipt model
type TxReceipt struct {
	TxHash            common.Hash    `json:"hash"`
	ContractAddress   common.Address `json:"contract_address"`
	GasUsed           uint64         `json:"gas_used"`
	BlockHash         common.Hash    `json:"block_hash,omitempty"`
	BlockNumber       *big.Int       `json:"block,omitempty"`
	TransactionIndex  uint           `json:"transaction_index"`
	PostState         []byte         `json:"root"`
	Status            uint64         `json:"status"`
	CumulativeGasUsed uint64         `json:"cumulative_gas_used"`
	Bloom             interface{}    `json:"logs_bloom"`
	Logs              []interface{}  `json:"logs"`
}

// TxTrace is generalized transaction trace model
type TxTrace struct {
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

// EthereumJsonRpcResponseError is a generic error representation for ethereum JSON-RPC responses
type EthereumJsonRpcResponseError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// EthereumJsonRpcResponse is a generic handler for ethereum JSON-RPC responses
type EthereumJsonRpcResponse struct {
	ID     interface{}                   `json:"id"`
	Result interface{}                   `json:"result"`
	Error  *EthereumJsonRpcResponseError `json:"error,omitempty"`
}

// EthereumWebsocketSubscriptionResponse is a generic handler for ethereum websocket subscription responses
type EthereumWebsocketSubscriptionResponse struct {
	ID     interface{}            `json:"id"`
	Params map[string]interface{} `json:"params"`
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

// Network contains the specific Ethereum network details (mainnet, etc.)
type Network struct {
	ApplicationID   *uuid.UUID       `sql:"type:uuid" json:"application_id,omitempty"`
	UserID          *uuid.UUID       `sql:"type:uuid" json:"user_id,omitempty"`
	Name            *string          `sql:"not null" json:"name"`
	Description     *string          `json:"description"`
	IsProduction    *bool            `sql:"not null" json:"-"` // deprecated
	Cloneable       *bool            `sql:"not null" json:"-"` // deprecated
	Enabled         *bool            `sql:"not null" json:"enabled"`
	ChainID         *string          `json:"chain_id"`                               // protocol-specific chain id
	SidechainID     *uuid.UUID       `sql:"type:uuid" json:"sidechain_id,omitempty"` // network id used as the transactional sidechain (or null)
	NetworkID       *uuid.UUID       `sql:"type:uuid" json:"network_id,omitempty"`   // network id used as the parent
	Config          *json.RawMessage `sql:"type:json not null" json:"config,omitempty"`
	EncryptedConfig *string          `sql:"-" json:"-"`
}

// Account contains the specific account user details
type Account struct {
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
	Wallet     *Wallet    `json:"-"`
}

// Wallet contains the specific wallet details
type Wallet struct {
	WalletID       *uuid.UUID `json:"wallet_id,omitempty"`
	ApplicationID  *uuid.UUID `json:"application_id,omitempty"`
	UserID         *uuid.UUID `json:"user_id,omitempty"`
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`

	VaultID *uuid.UUID `json:"vault_id,omitempty"`
	KeyID   *uuid.UUID `json:"key_id,omitempty"`

	Path        *string    `json:"path,omitempty"`
	Purpose     *int       `json:"purpose,omitempty"`
	Mnemonic    *string    `json:"mnemonic,omitempty"`
	ExtendedKey *bip32.Key `json:"-"`

	PublicKey  *string `json:"public_key,omitempty"`
	PrivateKey *string `json:"private_key,omitempty"`

	Wallet   *Wallet   `sql:"-" json:"-"`
	Accounts []Account `json:"-"`
}
