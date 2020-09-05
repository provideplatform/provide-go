package nchain

import (
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
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
