package nchain

import (
	"time"
)

// BaseledgerBlockHeader
type BaseledgerBlockHeaderResponse struct {
	Type  string `json:"type"`
	Value struct {
		Header struct {
			AppHash       string `json:"app_hash"`
			ChainID       string `json:"chain_id"`
			ConsensusHash string `json:"consensus_hash"`
			DataHash      string `json:"data_hash"`
			EvidenceHash  string `json:"evidence_hash"`
			Height        string `json:"height"`
			LastBlockID   struct {
				Hash  string `json:"hash"`
				Parts struct {
					Hash  string `json:"hash"`
					Total int    `json:"total"`
				} `json:"parts"`
			} `json:"last_block_id"`
			LastCommitHash     string    `json:"last_commit_hash"`
			LastResultsHash    string    `json:"last_results_hash"`
			NextValidatorsHash string    `json:"next_validators_hash"`
			ProposerAddress    string    `json:"proposer_address"`
			Time               time.Time `json:"time"`
			ValidatorsHash     string    `json:"validators_hash"`
			Version            struct {
				App   string `json:"app"`
				Block string `json:"block"`
			} `json:"version"`
		} `json:"header"`
		NumTxs           string `json:"num_txs"`
		ResultBeginBlock struct {
			Events []struct {
				Attributes []struct {
					Index bool   `json:"index"`
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"attributes"`
				Type string `json:"type"`
			} `json:"events"`
		} `json:"result_begin_block"`
		ResultEndBlock struct {
			ValidatorUpdates interface{} `json:"validator_updates"`
		} `json:"result_end_block"`
	} `json:"value"`
}

// TendermintBlockHeader represents a tendermint block header rpc response
type TendermintBlockHeader struct {
	Version struct {
		Block string `json:"block"`
	} `json:"version"`
	ChainID     string    `json:"chain_id"`
	Height      string    `json:"height"`
	Time        time.Time `json:"time"`
	LastBlockID struct {
		Hash  string `json:"hash"`
		Parts struct {
			Total int    `json:"total"`
			Hash  string `json:"hash"`
		} `json:"parts"`
	} `json:"last_block_id"`
	LastCommitHash     string `json:"last_commit_hash"`
	DataHash           string `json:"data_hash"`
	ValidatorsHash     string `json:"validators_hash"`
	NextValidatorsHash string `json:"next_validators_hash"`
	ConsensusHash      string `json:"consensus_hash"`
	AppHash            string `json:"app_hash"`
	LastResultsHash    string `json:"last_results_hash"`
	EvidenceHash       string `json:"evidence_hash"`
	ProposerAddress    string `json:"proposer_address"`
}

// TendermintBlock represents a tendermint full block rpc response
type TendermintBlock struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  struct {
		BlockID struct {
			Hash  string `json:"hash"`
			Parts struct {
				Total int    `json:"total"`
				Hash  string `json:"hash"`
			} `json:"parts"`
		} `json:"block_id"`
		Block struct {
			Header *TendermintBlockHeader `json:"header"`
			Data   struct {
				Txs []string `json:"txs"`
			} `json:"data"`
			Evidence struct {
				Evidence []interface{} `json:"evidence"`
			} `json:"evidence"`
			LastCommit struct {
				Height  string `json:"height"`
				Round   int    `json:"round"`
				BlockID struct {
					Hash  string `json:"hash"`
					Parts struct {
						Total int    `json:"total"`
						Hash  string `json:"hash"`
					} `json:"parts"`
				} `json:"block_id"`
				Signatures []struct {
					BlockIDFlag      int       `json:"block_id_flag"`
					ValidatorAddress string    `json:"validator_address"`
					Timestamp        time.Time `json:"timestamp"`
					Signature        string    `json:"signature"`
				} `json:"signatures"`
			} `json:"last_commit"`
		} `json:"block"`
	} `json:"result"`
}

// TendermintTx represents a tendermint transaction rpc response
type TendermintTx struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  struct {
		Hash     string `json:"hash"`
		Height   string `json:"height"`
		Index    int    `json:"index"`
		TxResult struct {
			Code      int    `json:"code"`
			Data      string `json:"data"`
			Log       string `json:"log"`
			Info      string `json:"info"`
			GasWanted string `json:"gas_wanted"`
			GasUsed   string `json:"gas_used"`
			Events    []struct {
				Type       string `json:"type"`
				Attributes []struct {
					Key   string `json:"key"`
					Value string `json:"value"`
					Index bool   `json:"index"`
				} `json:"attributes"`
			} `json:"events"`
			Codespace string `json:"codespace"`
		} `json:"tx_result"`
		Tx string `json:"tx"`
	} `json:"result"`
}
