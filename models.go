package provide

import "math/big"

// EthereumTxTraceResponse is returned upon successful contract execution
type EthereumTxTraceResponse struct {
	Result []struct {
		Action struct {
			CallType string `json:"callType"`
			From     string `json:"from"`
			Gas      string `json:"gas"`
			Init     string `json:"init"`
			Input    string `json:"input"`
			To       string `json:"to"`
			Value    string `json:"value"`
		} `json:"action"`
		BlockHash   string `json:"blockHash"`
		BlockNumber int    `json:"blockNumber"`
		Result      struct {
			Address string `json:"address"`
			Code    string `json:"code"`
			GasUsed string `json:"gasUsed"`
			Output  string `json:"output"`
		} `json:"result"`
		Subtraces           int           `json:"subtraces"`
		TraceAddress        []interface{} `json:"traceAddress"`
		TransactionHash     string        `json:"transactionHash"`
		TransactionPosition int           `json:"transactionPosition"`
		Type                string        `json:"type"`
	} `json:"result"`
}

// EthereumJsonRpcResponse is a generic handler for ethereum JSON-RPC responses
type EthereumJsonRpcResponse struct {
	ID     uint64      `json:"id"`
	Result interface{} `json:"result"`
}

// NetworkStatus provides network-agnostic status
type NetworkStatus struct {
	Block           uint64                 `json:"block"`            // current block
	ChainID         *big.Int               `json:"chain_id"`         // the chain id
	Height          *uint64                `json:"height"`           // total height of the blockchain; null after syncing completed
	LastBlockAt     *uint64                `json:"last_block_at"`    // unix timestamp of the last block; i.e., when the last block was collated
	PeerCount       uint64                 `json:"peer_count"`       // number of peers connected to the JSON-RPC client
	ProtocolVersion *string                `json:"protocol_version"` // protocol version
	State           *string                `json:"state"`            // i.e., syncing, synced, etc
	Syncing         bool                   `json:"syncing"`          // when true, the network is in the process of syncing the ledger; available functionaltiy will be network-specific
	Meta            map[string]interface{} `json:"meta"`             // network-specific metadata
}
