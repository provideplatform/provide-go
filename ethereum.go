package provide

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
)

// GetBlockNumber retrieves the latest block known to the JSON-RPC client
func GetBlockNumber(networkID, rpcURL string) *uint64 {
	params := make([]interface{}, 0)
	var resp = &EthereumJsonRpcResponse{}
	Log.Debugf("Attempting to fetch latest block number via JSON-RPC eth_blockNumber method")
	err := InvokeJsonRpcClient(networkID, rpcURL, "eth_blockNumber", params, &resp)
	if err != nil {
		Log.Warningf("Failed to invoke eth_blockNumber method via JSON-RPC; %s", err.Error())
		return nil
	}
	blockNumber, err := hexutil.DecodeBig(resp.Result.(string))
	if err != nil {
		return nil
	}
	_blockNumber := blockNumber.Uint64()
	return &_blockNumber
}

// GetChainConfig parses the cached network config mapped to the given
// `networkID`, if one exists; otherwise, the mainnet chain config is returned.
func GetChainConfig(networkID, rpcURL string) *params.ChainConfig {
	if cfg, ok := chainConfigs[networkID]; ok {
		return cfg
	}
	cfg := params.MainnetChainConfig
	chainID, err := strconv.ParseUint(networkID, 10, 0)
	if err != nil {
		cfg.ChainID = big.NewInt(int64(chainID))
		chainConfigs[networkID] = cfg
	}
	return cfg
}

// GetChainID retrieves the current chainID via JSON-RPC
func GetChainID(networkID, rpcURL string) *big.Int {
	ethClient, err := ResolveEthClient(networkID, rpcURL)
	if err != nil {
		Log.Warningf("Failed to read network id for *ethclient.Client instance: %s; %s", ethClient, err.Error())
		return nil
	}
	chainID, err := ethClient.NetworkID(context.TODO())
	if err != nil {
		Log.Warningf("Failed to read network id for *ethclient.Client instance: %s; %s", ethClient, err.Error())
		return nil
	}
	if chainID != nil {
		Log.Debugf("Received chain id from *ethclient.Client instance: %s", ethClient, chainID)
	}
	return chainID
}

// GetGasPrice returns the gas price
func GetGasPrice(networkID, rpcURL string) *string {
	params := make([]interface{}, 0)
	var resp = &EthereumJsonRpcResponse{}
	Log.Debugf("Attempting to fetch gas price via JSON-RPC eth_gasPrice method")
	err := InvokeJsonRpcClient(networkID, rpcURL, "eth_gasPrice", params, &resp)
	if err != nil {
		Log.Warningf("Failed to invoke eth_gasPrice method via JSON-RPC; %s", err.Error())
		return nil
	}
	return stringOrNil(resp.Result.(string))
}

// GetLatestBlock retrieves the best block known to the JSON-RPC client
func GetLatestBlock(networkID, rpcURL string) (uint64, error) {
	status, err := GetNetworkStatus(networkID, rpcURL)
	if err != nil {
		return 0, err
	}
	return status.Block, nil
}

// GetBlockByNumber retrieves a given block by number
func GetBlockByNumber(networkID, rpcURL string, blockNumber uint64) (*EthereumJsonRpcResponse, error) {
	var jsonRpcResponse = &EthereumJsonRpcResponse{}
	err := InvokeJsonRpcClient(networkID, rpcURL, "eth_getBlockByNumber", []interface{}{hexutil.EncodeUint64(blockNumber), true}, &jsonRpcResponse)
	return jsonRpcResponse, err
}

// GetNativeBalance retrieves a wallet's native currency balance
func GetNativeBalance(networkID, rpcURL, addr string) (*big.Int, error) {
	client, err := DialJsonRpc(networkID, rpcURL)
	if err != nil {
		return nil, err
	}
	return client.BalanceAt(context.TODO(), common.HexToAddress(addr), nil)
}

// GetNetworkStatus retrieves current metadata from the JSON-RPC client;
// returned struct includes block height, chainID, number of connected peers,
// protocol version, and syncing state.
func GetNetworkStatus(networkID, rpcURL string) (*NetworkStatus, error) {
	ethClient, err := ResolveEthClient(networkID, rpcURL)
	if err != nil || rpcURL == "" || ethClient == nil {
		meta := map[string]interface{}{
			"error": nil,
		}
		if err != nil {
			Log.Warningf("Failed to dial JSON-RPC host: %s; %s", rpcURL, err.Error())
			meta["error"] = err.Error()
		} else if rpcURL == "" {
			meta["error"] = "No 'full-node' JSON-RPC URL configured or resolvable"
		} else if ethClient == nil {
			meta["error"] = "Configured 'full-node' JSON-RPC client not resolved"
		}
		return &NetworkStatus{
			State: stringOrNil("configuring"),
			Meta:  meta,
		}, nil
	}

	defer func() {
		if r := recover(); r != nil {
			Log.Debugf("Recovered from attempting to retrieve sync progress from JSON-RPC host: %s", rpcURL)
			clearCachedClients(networkID)
		}
	}()

	syncProgress, err := GetSyncProgress(ethClient)
	if err != nil {
		Log.Warningf("Failed to read sync progress using JSON-RPC host; %s", err.Error())
		clearCachedClients(networkID)
		return nil, err
	}
	var state string
	var block uint64        // current block; will be less than height while syncing in progress
	var height *uint64      // total number of blocks
	var lastBlockAt *uint64 // unix timestamp of last block
	chainID := GetChainID(networkID, rpcURL)
	peers := GetPeerCount(networkID, rpcURL)
	protocolVersion := GetProtocolVersion(networkID, rpcURL)
	meta := map[string]interface{}{}
	var syncing = false
	if syncProgress == nil {
		state = "synced"
		hdr, err := ethClient.HeaderByNumber(context.TODO(), nil)
		var jsonRpcResponse *EthereumJsonRpcResponse
		if err != nil && hdr == nil {
			Log.Warningf("Failed to read latest block header for %s using JSON-RPC host; %s", rpcURL, err.Error())
			err = InvokeJsonRpcClient(networkID, rpcURL, "eth_getBlockByNumber", []interface{}{"latest", true}, &jsonRpcResponse)
			if err != nil {
				Log.Warningf("Failed to read latest block header for %s using JSON-RPC host; %s", rpcURL, err.Error())
				err = InvokeJsonRpcClient(networkID, rpcURL, "eth_getBlockByNumber", []interface{}{"earliest", true}, &jsonRpcResponse)
				if err != nil {
					Log.Warningf("Failed to read earliest block header for %s using JSON-RPC host; %s", rpcURL, err.Error())
					return nil, err
				}
			}
		}
		block = hdr.Number.Uint64()
		jsonRpcResponse, err = GetBlockByNumber(networkID, rpcURL, block)
		if err == nil {
			if lastBlock, lastBlockOk := jsonRpcResponse.Result.(map[string]interface{}); lastBlockOk {
				Log.Debugf("Got JSON-RPC response; %s", lastBlock)
				meta["last_block"] = lastBlock
				if blockTimestamp, blockTimestampOk := lastBlock["timestamp"].(string); blockTimestampOk {
					*lastBlockAt, err = hexutil.DecodeUint64(blockTimestamp)
					if err == nil {
						Log.Warningf("Failed to decode latest block timestamp for %s using JSON-RPC host; %s", rpcURL, err.Error())
					}
				}
			}
		}
	} else {
		block = syncProgress.CurrentBlock
		height = &syncProgress.HighestBlock
		syncing = true
	}
	return &NetworkStatus{
		Block:           block,
		Height:          height,
		ChainID:         chainID,
		PeerCount:       peers,
		LastBlockAt:     lastBlockAt,
		ProtocolVersion: protocolVersion,
		State:           stringOrNil(state),
		Syncing:         syncing,
		Meta:            meta,
	}, nil
}

// GetPeerCount returns the number of peers currently connected to the JSON-RPC client
func GetPeerCount(networkID, rpcURL string) uint64 {
	var peerCount uint64
	params := make([]interface{}, 0)
	var resp = &EthereumJsonRpcResponse{}
	Log.Debugf("Attempting to fetch peer count via net_peerCount method via JSON-RPC")
	err := InvokeJsonRpcClient(networkID, rpcURL, "net_peerCount", params, &resp)
	if err != nil {
		Log.Debugf("Attempting to fetch peer count via parity_netPeers method via JSON-RPC")
		err := InvokeJsonRpcClient(networkID, rpcURL, "parity_netPeers", params, &resp)
		Log.Warningf("Failed to invoke parity_netPeers method via JSON-RPC; %s", err.Error())
		return 0
	}
	if peerCountStr, ok := resp.Result.(string); ok {
		peerCount, err = hexutil.DecodeUint64(peerCountStr)
		if err != nil {
			return 0
		}
	}
	return peerCount
}

// GetProtocolVersion returns the JSON-RPC client protocol version
func GetProtocolVersion(networkID, rpcURL string) *string {
	params := make([]interface{}, 0)
	var resp = &EthereumJsonRpcResponse{}
	Log.Debugf("Attempting to fetch protocol version via JSON-RPC eth_protocolVersion method")
	err := InvokeJsonRpcClient(networkID, rpcURL, "eth_protocolVersion", params, &resp)
	if err != nil {
		Log.Debugf("Attempting to fetch protocol version via JSON-RPC net_version method")
		err := InvokeJsonRpcClient(networkID, rpcURL, "net_version", params, &resp)

		Log.Warningf("Failed to invoke eth_protocolVersion method via JSON-RPC; %s", err.Error())
		return nil
	}
	return stringOrNil(resp.Result.(string))
}

// GetCode retrieves the code stored at the named address in the given scope;
// scope can be a block number, latest, earliest or pending
func GetCode(networkID, rpcURL, addr, scope string) (*string, error) {
	params := make([]interface{}, 0)
	params = append(params, addr)
	params = append(params, scope)
	var resp = &EthereumJsonRpcResponse{}
	Log.Debugf("Attempting to fetch code from %s via eth_getCode JSON-RPC method", addr)
	err := InvokeJsonRpcClient(networkID, rpcURL, "eth_getCode", params, &resp)
	if err != nil {
		Log.Warningf("Failed to invoke eth_getCode method via JSON-RPC; %s", err.Error())
		return nil, err
	}
	return stringOrNil(resp.Result.(string)), nil
}

// GetSyncProgress retrieves the status of the current network sync
func GetSyncProgress(client *ethclient.Client) (*ethereum.SyncProgress, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
	progress, err := client.SyncProgress(ctx)
	if err != nil {
		Log.Warningf("Failed to read sync progress for *ethclient.Client instance: %s; %s", client, err.Error())
		cancel()
		return nil, err
	}
	if progress != nil {
		Log.Debugf("Latest synced block reported by *ethclient.Client instance: %v [of %v]", client, progress.CurrentBlock, progress.HighestBlock)
	}
	cancel()
	return progress, nil
}

// GetTokenBalance retrieves a token balance for a specific token contract and network address
func GetTokenBalance(networkID, rpcURL, tokenAddr, addr string, contractABI interface{}) (*big.Int, error) {
	var balance *big.Int
	abi, err := parseContractABI(contractABI)
	if err != nil {
		return nil, err
	}
	client, err := DialJsonRpc(networkID, rpcURL)
	gasPrice, _ := client.SuggestGasPrice(context.TODO())
	to := common.HexToAddress(tokenAddr)
	msg := ethereum.CallMsg{
		From:     common.HexToAddress(addr),
		To:       &to,
		Gas:      0,
		GasPrice: gasPrice,
		Value:    nil,
		Data:     common.FromHex(HashFunctionSelector("balanceOf(address)")),
	}
	result, _ := client.CallContract(context.TODO(), msg, nil)
	if method, ok := abi.Methods["balanceOf"]; ok {
		method.Outputs.Unpack(&balance, result)
		if balance != nil {
			symbol, _ := GetTokenSymbol(networkID, rpcURL, addr, tokenAddr, contractABI)
			Log.Debugf("Read %s token balance (%v) from token contract address: %s", symbol, balance, addr)
		}
	} else {
		Log.Warningf("Unable to read balance of unsupported token contract address: %s", tokenAddr)
	}
	return balance, nil
}

// GetTokenSymbol attempts to retrieve the symbol of a token presumed to be deployed at the given token contract address
func GetTokenSymbol(networkID, rpcURL, from, tokenAddr string, contractABI interface{}) (*string, error) {
	client, err := DialJsonRpc(networkID, rpcURL)
	if err != nil {
		return nil, err
	}
	_abi, err := parseContractABI(contractABI)
	if err != nil {
		return nil, err
	}
	to := common.HexToAddress(tokenAddr)
	msg := ethereum.CallMsg{
		From:     common.HexToAddress(from),
		To:       &to,
		Gas:      0,
		GasPrice: big.NewInt(0),
		Value:    nil,
		Data:     common.FromHex(HashFunctionSelector("symbol()")),
	}
	result, _ := client.CallContract(context.TODO(), msg, nil)
	var symbol string
	if method, ok := _abi.Methods["symbol"]; ok {
		err = method.Outputs.Unpack(&symbol, result)
		if err != nil {
			Log.Warningf("Failed to read token symbol from deployed token contract %s; %s", tokenAddr, err.Error())
		}
	}
	return stringOrNil(symbol), nil
}

// TraceTx returns the VM traces; requires parity JSON-RPC client and the node must
// be configured with `--fat-db on --tracing on --pruning archive`
func TraceTx(networkID, rpcURL string, hash *string) (interface{}, error) {
	var addr = *hash
	if !strings.HasPrefix(addr, "0x") {
		addr = fmt.Sprintf("0x%s", addr)
	}
	params := make([]interface{}, 0)
	params = append(params, addr)
	var result = &EthereumTxTraceResponse{}
	Log.Debugf("Attempting to trace tx via trace_transaction method via JSON-RPC; tx hash: %s", addr)
	err := InvokeJsonRpcClient(networkID, rpcURL, "trace_transaction", params, &result)
	if err != nil {
		Log.Warningf("Failed to invoke trace_transaction method via JSON-RPC; %s", err.Error())
		return nil, err
	}
	return result, nil
}

// GetTxReceipt retrieves the full transaction receipt via JSON-RPC given the transaction hash
func GetTxReceipt(networkID, rpcURL, txHash, from string) (*types.Receipt, error) {
	client, err := DialJsonRpc(networkID, rpcURL)
	if err != nil {
		Log.Warningf("Failed to retrieve tx receipt for broadcast tx: %s; %s", txHash, err.Error())
		return nil, err
	}
	Log.Debugf("Attempting to retrieve tx receipt for broadcast tx: %s", txHash)
	return client.TransactionReceipt(context.TODO(), common.HexToHash(txHash))
}
