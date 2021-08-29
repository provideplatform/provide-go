package nchain

import "math/big"

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

// TxReceipt is generalized transaction receipt model
type TxReceipt struct {
	TxHash            []byte        `json:"hash"`
	ContractAddress   []byte        `json:"contract_address"`
	GasUsed           uint64        `json:"gas_used"`
	BlockHash         []byte        `json:"block_hash,omitempty"`
	BlockNumber       *big.Int      `json:"block,omitempty"`
	TransactionIndex  uint          `json:"transaction_index"`
	PostState         []byte        `json:"root"`
	Status            uint64        `json:"status"`
	CumulativeGasUsed uint64        `json:"cumulative_gas_used"`
	Bloom             interface{}   `json:"logs_bloom"`
	Logs              []interface{} `json:"logs"`
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

// EthereumWebsocketSubscriptionResponse is a generic handler for ethereum websocket subscription responses
type EthereumWebsocketSubscriptionResponse struct {
	ID     interface{}            `json:"id"`
	Params map[string]interface{} `json:"params"`
}
