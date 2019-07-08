package provide

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/ripemd160"
)

// The purpose of this class is to expose generic transactional and ABI-related helper
// methods; ethereum.go is a convenience wrapper around JSON-RPC.

// It also caches JSON-RPC client instances in a few flavors (*ethclient.Client and *ethrpc.Client)
// and maps them to an arbitrary `networkID` after successfully dialing the given RPC URL.

var bcoinRPCClients = map[string][]*rpcclient.Client{} // mapping of network ids to *ethrpc.Client instances
var bcoinMutex = &sync.Mutex{}
var bcoinaddrjs *string

// func init() {
// 	bcoinaddr, err := ioutil.ReadFile("./bcoinaddr.js")
// 	if err != nil {
// 		Log.Panicf("Failed to read bcoinaddr.js")
// 	}
// 	bcoinaddrjs = stringOrNil(string(bcoinaddr))
// }

func bcoinClearCachedClients(networkID string) {
	bcoinMutex.Lock()
	for i := range bcoinRPCClients[networkID] {
		bcoinRPCClients[networkID][i].Shutdown()
	}

	bcoinRPCClients[networkID] = make([]*rpcclient.Client, 0)
	bcoinMutex.Unlock()
}

// BcoinGenerateKeyPair generates a bitcoin address using the given hex representation
// of a secp256k1 private key; see http://bcoin.io/guides/generate-address.html; returns
// the address and private key, or an error
func BcoinGenerateKeyPair(version byte) (address *string, privateKey *ecdsa.PrivateKey, err error) {
	// Generate a secp256k1 keypair
	privateKey, err = ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		Log.Warningf("Failed to generate bcoin keypair; %s", err.Error())
		return nil, nil, err
	}

	// Take the corresponding public key generated with it (65 bytes, 1 byte 0x04, 32 bytes corresponding to X coordinate, 32 bytes corresponding to Y coordinate)
	buf := &bytes.Buffer{}
	buf.WriteByte(0x04)
	buf.Write(privateKey.Public().(*ecdsa.PublicKey).X.Bytes())
	buf.Write(privateKey.Public().(*ecdsa.PublicKey).Y.Bytes())

	publicKey := buf.Bytes()
	var hashedPublicKey []byte

	// Perform SHA-256 hashing on the public key
	s256digest := sha256.New()
	s256digest.Write(publicKey)
	hashedPublicKey = s256digest.Sum(nil)

	// Perform RIPEMD-160 hashing on the result of SHA-256
	ripemd160Digest := ripemd160.New()
	ripemd160Digest.Write(hashedPublicKey)
	hashedPublicKey = ripemd160Digest.Sum(nil)

	// Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
	extendedBuf := &bytes.Buffer{}
	extendedBuf.WriteByte(version)
	extendedBuf.Write(hashedPublicKey)
	addr := extendedBuf.Bytes()

	// Perform SHA-256 hash on the extended RIPEMD-160 result
	s256digest = sha256.New()
	s256digest.Write(addr)
	hashedPublicKey = s256digest.Sum(nil)

	// Perform SHA-256 hash on the result of the previous SHA-256 hash
	s256digest = sha256.New()
	s256digest.Write(hashedPublicKey)
	hashedPublicKey = s256digest.Sum(nil)

	// Take the first 4 bytes of the second SHA-256 hash. This is the address checksum
	checksumBuf := &bytes.Buffer{}
	checksumBuf.WriteByte(hashedPublicKey[0])
	checksumBuf.WriteByte(hashedPublicKey[1])
	checksumBuf.WriteByte(hashedPublicKey[2])
	checksumBuf.WriteByte(hashedPublicKey[3])
	checksum := checksumBuf.Bytes()

	// Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.
	binaryAddrBuf := &bytes.Buffer{}
	binaryAddrBuf.Write(addr)
	binaryAddrBuf.Write(checksum)
	addr = binaryAddrBuf.Bytes()

	// Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format
	address = stringOrNil(base58.Encode(addr))

	return address, privateKey, err
}

// BcoinDialJsonRpc - dials and caches a new JSON-RPC client instance at the JSON-RPC url and caches it using the given network id
func BcoinDialJsonRpc(networkID, rpcURL, rpcAPIUser, rpcAPIKey string) (*rpcclient.Client, error) {
	var client *rpcclient.Client

	if networkClients, _ := bcoinRPCClients[networkID]; len(networkClients) == 0 {
		rpcClient, err := BcoinResolveJsonRpcClient(networkID, rpcURL, rpcAPIUser, rpcAPIKey)
		if err != nil {
			Log.Warningf("Failed to dial JSON-RPC host: %s", rpcURL)
			return nil, err
		}
		bcoinMutex.Lock()
		bcoinRPCClients[networkID] = append(bcoinRPCClients[networkID], rpcClient)
		bcoinMutex.Unlock()
		Log.Debugf("Dialed JSON-RPC host @ %s", rpcURL)
	} else {
		client = bcoinRPCClients[networkID][0]
	}

	return client, nil
}

// BcoinInvokeJsonRpcClient - invokes the JSON-RPC client for the given network and url
func BcoinInvokeJsonRpcClient(networkID, rpcURL, rpcAPIUser, rpcAPIKey, method string, params []interface{}, response interface{}) error {
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
	host := rpcURL
	httpIdx := strings.Index(rpcURL, "http://")
	if httpIdx == 0 {
		host = strings.Replace(rpcURL, "http://", fmt.Sprintf("http://%s:%s@", rpcAPIUser, rpcAPIKey), 1)
	} else {
		httpsIdx := strings.Index(rpcURL, "https://")
		if httpsIdx == 0 {
			host = strings.Replace(rpcURL, "https://", fmt.Sprintf("https://%s:%s@", rpcAPIUser, rpcAPIKey), 1)
		}
	}
	resp, err := client.Post(host, "application/json", bytes.NewReader(body))
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
	if networkClients, _ := bcoinRPCClients[networkID]; len(networkClients) == 0 {
		host := rpcURL
		httpIdx := strings.Index(rpcURL, "http://")
		if httpIdx == 0 {
			host = rpcURL[7:]
		} else {
			httpsIdx := strings.Index(rpcURL, "https://")
			if httpsIdx == 0 {
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
		bcoinRPCClients[networkID] = append(networkClients, client)
		bcoinMutex.Unlock()
		Log.Debugf("Dialed JSON-RPC host @ %s", rpcURL)
	} else {
		client = bcoinRPCClients[networkID][0]
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
	var height *int64       // total number of blocks
	var lastBlockAt *uint64 // unix timestamp of last block
	var difficulty *float64
	var chainInfo map[string]interface{}
	chainID := networkID
	// peers := BcoinGetPeerCount(networkID, rpcURL)

	height, err = BcoinGetHeight(networkID, rpcURL, rpcAPIUser, rpcAPIKey)
	if err != nil {
		Log.Warningf("Failed to read chain height for %s using JSON-RPC host; %s", rpcURL, err.Error())
		return nil, err
	}

	chainInfoResp, err := BcoinGetChainInfo(networkID, rpcURL, rpcAPIUser, rpcAPIKey)
	if err != nil {
		Log.Warningf("Failed to read chain info for %s using JSON-RPC host; %s", rpcURL, err.Error())
		return nil, err
	}
	chainInfo = chainInfoResp["result"].(map[string]interface{})

	bestBlockHash, _ := chainInfo["bestblockhash"].(string)
	resp, err := BcoinGetBlock(networkID, rpcURL, rpcAPIUser, rpcAPIKey, bestBlockHash)
	if err != nil {
		Log.Warningf("Failed to get the latest block header for hash: %s; %s", bestBlockHash, err.Error())
		return nil, err
	}

	// difficulty = &chainInfo.Difficulty
	Log.Debugf("%s", resp)
	meta := map[string]interface{}{
		"chain_info":        chainInfo,
		"difficulty":        difficulty,
		"last_block_header": resp,
		"last_block_tx":     resp["transactions"],
	}

	lastBlockTime := resp["time"].(float64)
	_lastBlockAt := uint64(lastBlockTime)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode block timestamp; %s", err.Error())
	}
	lastBlockAt = &_lastBlockAt

	var _height *uint64
	if height != nil {
		ht := uint64(*height)
		_height = &ht
		block = ht
	}

	return &NetworkStatus{
		Block:           block,
		Height:          _height,
		ChainID:         stringOrNil(chainID),
		PeerCount:       0,
		LastBlockAt:     lastBlockAt,
		ProtocolVersion: nil,
		State:           stringOrNil(state),
		Syncing:         false,
		Meta:            meta,
	}, nil
}

// BcoinGetDifficulty retrieves the current difficulty target
func BcoinGetDifficulty(networkID, rpcURL, rpcAPIUser, rpcAPIKey string) (*float64, error) {
	btcClient, err := BcoinResolveJsonRpcClient(networkID, rpcURL, rpcAPIUser, rpcAPIKey)
	if err != nil {
		Log.Warningf("Failed to get the difficulty target; %s", err.Error())
		return nil, err
	}
	difficulty, err := btcClient.GetDifficulty()
	if err != nil {
		Log.Warningf("Failed to get the difficulty target; %s", err.Error())
		return nil, err
	}
	return &difficulty, err
}

// BcoinGetHeight retrieves the height of the longest chain
func BcoinGetHeight(networkID, rpcURL, rpcAPIUser, rpcAPIKey string) (*int64, error) {
	btcClient, err := BcoinResolveJsonRpcClient(networkID, rpcURL, rpcAPIUser, rpcAPIKey)
	if err != nil {
		Log.Warningf("Failed to get the chain height; %s", err.Error())
		return nil, err
	}
	height, err := btcClient.GetBlockCount()
	if err != nil {
		Log.Warningf("Failed to get the chain height; %s", err.Error())
		return nil, err
	}
	return &height, err
}

// BcoinGetChainInfo retrieves chain info
func BcoinGetChainInfo(networkID, rpcURL, rpcAPIUser, rpcAPIKey string) (map[string]interface{}, error) {
	var resp map[string]interface{}
	err := BcoinInvokeJsonRpcClient(networkID, rpcURL, rpcAPIUser, rpcAPIKey, "getblockchaininfo", make([]interface{}, 0), &resp)
	if err != nil {
		Log.Warningf("Failed to get chain info; %s", err.Error())
		return nil, err
	}
	return resp, err
}

// BcoinGetHeader retrieves the latsest block
func BcoinGetHeader(networkID, rpcURL, rpcAPIUser, rpcAPIKey, hash string) (map[string]interface{}, error) {
	var resp map[string]interface{}
	err := BcoinInvokeJsonRpcClient(networkID, rpcURL, rpcAPIUser, rpcAPIKey, "getblockheader", []interface{}{hash}, &resp)
	if err != nil {
		Log.Warningf("Failed to get block header with hash: %s; %s", hash, err.Error())
		return nil, err
	}
	result, _ := resp["result"].(map[string]interface{})
	return result, err
}

// BcoinGetBlock retrieves the latsest block
func BcoinGetBlock(networkID, rpcURL, rpcAPIUser, rpcAPIKey, hash string) (map[string]interface{}, error) {
	var resp map[string]interface{}
	err := BcoinInvokeJsonRpcClient(networkID, rpcURL, rpcAPIUser, rpcAPIKey, "getblock", []interface{}{hash}, &resp)
	if err != nil {
		Log.Warningf("Failed to get block with hash: %s; %s", hash, err.Error())
		return nil, err
	}
	result, _ := resp["result"].(map[string]interface{})
	return result, err
}
