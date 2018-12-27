package provide

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
)

// The purpose of this class is to expose generic transactional and ABI-related helper
// methods; ethereum.go is a convenience wrapper around JSON-RPC.

// It also caches JSON-RPC client instances in a few flavors (*ethclient.Client and *ethrpc.Client)
// and maps them to an arbitrary `networkID` after successfully dialing the given RPC URL.

var bcoinRpcClients = map[string][]*rpcclient.Client{} // mapping of network ids to *ethrpc.Client instances
var bcoinMutex = &sync.Mutex{}

func bcoinClearCachedClients(networkID string) {
	bcoinMutex.Lock()
	for i := range bcoinRpcClients[networkID] {
		bcoinRpcClients[networkID][i].Shutdown()
	}

	bcoinRpcClients[networkID] = make([]*rpcclient.Client, 0)
	bcoinMutex.Unlock()
}

// BcoinDialJsonRpc - dials and caches a new JSON-RPC client instance at the JSON-RPC url and caches it using the given network id
func BcoinDialJsonRpc(networkID, rpcURL, rpcAPIUser, rpcAPIKey string) (*rpcclient.Client, error) {
	var client *rpcclient.Client

	if networkClients, _ := bcoinRpcClients[networkID]; len(networkClients) == 0 {
		rpcClient, err := BcoinResolveJsonRpcClient(networkID, rpcURL, rpcAPIUser, rpcAPIKey)
		if err != nil {
			Log.Warningf("Failed to dial JSON-RPC host: %s", rpcURL)
			return nil, err
		}
		bcoinMutex.Lock()
		bcoinRpcClients[networkID] = append(bcoinRpcClients[networkID], rpcClient)
		bcoinMutex.Unlock()
		Log.Debugf("Dialed JSON-RPC host @ %s", rpcURL)
	} else {
		client = bcoinRpcClients[networkID][0]
	}

	return client, nil
}

// BcoinInvokeJsonRpcClient - invokes the JSON-RPC client for the given network and url
func BcoinInvokeJsonRpcClient(networkID, rpcURL, method string, params []interface{}, response interface{}) error {
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		Timeout: time.Second * 60,
	}
	payload := map[string]interface{}{
		"method":  method,
		"params":  params,
		"id":      networkID,
		"jsonrpc": "2.0",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		Log.Warningf("Failed to marshal JSON payload for %s JSON-RPC invocation; %s", method, err.Error())
		return err
	}
	resp, err := client.Post(rpcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		Log.Warningf("Failed to invoke JSON-RPC method: %s; %s", method, err.Error())
		return err
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	err = json.Unmarshal(buf.Bytes(), response)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal %s JSON-RPC response: %s; %s", method, buf.Bytes(), err.Error())
	}
	Log.Debugf("Invocation of JSON-RPC method %s succeeded (%v-byte response)", method, buf.Len())
	return nil
}

// BcoinResolveJsonRpcClient resolves a cached *ethclient.Client client or dials and caches a new instance
func BcoinResolveJsonRpcClient(networkID, rpcURL, rpcAPIUser, rpcAPIKey string) (*rpcclient.Client, error) {
	var client *rpcclient.Client
	if networkClients, _ := bcoinRpcClients[networkID]; len(networkClients) == 0 {
		host := rpcURL
		httpIdx := strings.Index(rpcURL, "http://")
		if httpIdx == 0 {
			host = rpcURL[7:]
		} else {
			httpIdx := strings.Index(rpcURL, "https://")
			if httpIdx == 0 {
				host = rpcURL[8:]
			}
		}
		client, err := rpcclient.New(&rpcclient.ConnConfig{
			Host:         host,
			User:         rpcAPIUser,
			Pass:         rpcAPIKey,
			HTTPPostMode: true,
			DisableTLS:   true,
		}, nil)
		if err != nil {
			log.Fatal(err)
		}
		if err != nil {
			Log.Warningf("Failed to dial RPC client for JSON-RPC host: %s", rpcURL)
			return nil, err
		}
		bcoinMutex.Lock()
		bcoinRpcClients[networkID] = append(networkClients, client)
		bcoinMutex.Unlock()
		Log.Debugf("Dialed JSON-RPC host @ %s", rpcURL)
	} else {
		client = bcoinRpcClients[networkID][0]
		Log.Debugf("Resolved JSON-RPC host @ %s", rpcURL)
	}
	return client, nil
}

// BcoinGetNetworkStatus retrieves current metadata from the JSON-RPC client;
// returned struct includes block height, number of connected peers, protocol
// version, and syncing state.
func BcoinGetNetworkStatus(networkID, rpcURL, rpcAPIUser, rpcAPIKey string) (*NetworkStatus, error) {
	btcClient, err := BcoinDialJsonRpc(networkID, rpcURL, rpcAPIUser, rpcAPIKey)
	if err != nil || rpcURL == "" || btcClient == nil {
		meta := map[string]interface{}{
			"error": nil,
		}
		if err != nil {
			Log.Warningf("Failed to dial JSON-RPC host: %s; %s", rpcURL, err.Error())
			meta["error"] = err.Error()
		} else if rpcURL == "" {
			meta["error"] = "No 'full-node' JSON-RPC URL configured or resolvable"
		} else if btcClient == nil {
			meta["error"] = "Configured 'full-node' JSON-RPC client not resolved"
		}
		return &NetworkStatus{
			State: stringOrNil("configuring"),
			Meta:  meta,
		}, nil
	}

	defer func() {
		if r := recover(); r != nil {
			Log.Debugf("Recovered from failed attempt to retrieve network sync progress from JSON-RPC host: %s", rpcURL)
			bcoinClearCachedClients(networkID)
		}
	}()

	state := "synced"       // FIXME
	var block uint64        // current block; will be less than height while syncing in progress
	var height *uint64      // total number of blocks
	var lastBlockAt *uint64 // unix timestamp of last block
	chainID := networkID
	// peers := BcoinGetPeerCount(networkID, rpcURL)

	resp, err := BcoinGetLatestBlock(networkID, rpcURL, rpcAPIUser, rpcAPIKey)
	if err != nil {
		Log.Warningf("Failed to read latest block for %s using JSON-RPC host; %s", rpcURL, err.Error())
		return nil, err
	}

	meta := map[string]interface{}{
		"last_block_header": resp.Header,
	}

	_lastBlockAt := uint64(resp.Header.Timestamp.Unix())
	if err != nil {
		return nil, fmt.Errorf("Unable to decode block timestamp; %s", err.Error())
	}
	lastBlockAt = &_lastBlockAt

	return &NetworkStatus{
		Block:           block,
		Height:          height,
		ChainID:         stringOrNil(chainID),
		PeerCount:       0,
		LastBlockAt:     lastBlockAt,
		ProtocolVersion: nil,
		State:           stringOrNil(state),
		Syncing:         false,
		Meta:            meta,
	}, nil
}

// BcoinGetLatestBlock retrieves the latsest block
func BcoinGetLatestBlock(networkID, rpcURL, rpcAPIUser, rpcAPIKey string) (*wire.MsgBlock, error) {
	btcClient, err := BcoinResolveJsonRpcClient(networkID, rpcURL, rpcAPIUser, rpcAPIKey)
	if err != nil {
		Log.Warningf("Failed to get the latest block; %s", err.Error())
		return nil, err
	}
	bestBlockHash, err := btcClient.GetBestBlockHash()
	if err != nil {
		Log.Warningf("Failed to get the latest block hash; %s", err.Error())
		return nil, err
	}
	bestBlock, err := btcClient.GetBlock(bestBlockHash)
	if err != nil {
		Log.Warningf("Failed to get the latest block for hash: %s; %s", bestBlockHash, err.Error())
		return nil, err
	}
	return bestBlock, err
}
