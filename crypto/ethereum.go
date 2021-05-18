package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	ethrpc "github.com/ethereum/go-ethereum/rpc"
	uuid "github.com/kthomas/go.uuid"
	"golang.org/x/crypto/scrypt"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	api "github.com/provideservices/provide-go/api/nchain"
	prvdcommon "github.com/provideservices/provide-go/common"
)

// The purpose of this class is to expose generic transactional and ABI-related helper
// methods; ethereum.go is a convenience wrapper around JSON-RPC.

// It also caches JSON-RPC client instances in a few flavors (*ethclient.Client and *ethrpc.Client)
// and maps them to an arbitrary `rpcClientKey` after successfully dialing the given RPC URL.

const kovanChainID = uint64(42)

var chainConfigs = map[string]*params.ChainConfig{}        // mapping of rpc client keys to *params.ChainConfig
var ethclientRpcClients = map[string][]*ethclient.Client{} // mapping of rpc client keys to *ethclient.Client instances
var ethrpcClients = map[string][]*ethrpc.Client{}          // mapping of rpc client keys to *ethrpc.Client instances

var evmMutex = &sync.Mutex{}

const defaultRpcTimeout = time.Second * 60

var customRpcTimeout *time.Duration

const defaultEvmSyncTimeout = time.Second * 5

var customEvmSyncTimeout *time.Duration

func rpcTimeout() time.Duration {
	// check for custom timeout
	if customRpcTimeout != nil {
		return *customRpcTimeout
	}

	// if nil check for env var
	envRpcTimeout := os.Getenv("RPC_TIMEOUT")
	if envRpcTimeout == "" {
		return defaultRpcTimeout
	}

	// convert string to int64
	timeout, err := strconv.ParseInt(envRpcTimeout, 10, 64)
	if err != nil {
		prvdcommon.Log.Debugf("Error parsing custom rpc timeout. using default rpc timeout. Error: %s", err.Error())
		return defaultRpcTimeout
	}

	//convert to time.Duration
	timeoutInSeconds := time.Duration(timeout) * time.Second

	//set custom timeout and return custom timeout
	prvdcommon.Log.Debugf("Using custom rpc timeout of %v for rpc requests", timeout)
	customRpcTimeout = &timeoutInSeconds

	return *customRpcTimeout
}

func evmSyncTimeout() time.Duration {
	// check for custom timeout
	if customEvmSyncTimeout != nil {
		return *customEvmSyncTimeout
	}

	// if nil check for env var
	envEvmSyncTimeout := os.Getenv("EVM_SYNC_TIMEOUT")
	if envEvmSyncTimeout == "" {
		prvdcommon.Log.Debugf("Using default EVM Sync timeout of %v seconds", defaultEvmSyncTimeout)
		return defaultEvmSyncTimeout
	}

	// convert string to int64
	timeout, err := strconv.ParseInt(envEvmSyncTimeout, 10, 64)
	if err != nil {
		prvdcommon.Log.Debugf("Error parsing custom EVM sync timeout. using default(%v seconds). Error: %s", defaultEvmSyncTimeout, err.Error())
		return defaultEvmSyncTimeout
	}

	//convert to time.Duration
	timeoutInSeconds := time.Duration(timeout) * time.Second

	//set custom timeout and return custom timeout
	prvdcommon.Log.Debugf("Using custom EVM sync timeout of %v seconds", timeout)
	customEvmSyncTimeout = &timeoutInSeconds

	return *customEvmSyncTimeout
}

func evmClearCachedClients(rpcClientKey string) {
	evmMutex.Lock()
	delete(chainConfigs, rpcClientKey)
	for i := range ethrpcClients[rpcClientKey] {
		ethrpcClients[rpcClientKey][i].Close()
	}
	for i := range ethclientRpcClients[rpcClientKey] {
		ethclientRpcClients[rpcClientKey][i].Close()
	}
	ethrpcClients[rpcClientKey] = make([]*ethrpc.Client, 0)
	ethclientRpcClients[rpcClientKey] = make([]*ethclient.Client, 0)
	evmMutex.Unlock()
}

// EVMDialJsonRpc - dials and caches a new JSON-RPC client instance at the JSON-RPC url and caches it using the given network id
func EVMDialJsonRpc(rpcClientKey, rpcURL string) (*ethclient.Client, error) {
	var client *ethclient.Client

	if networkClients, _ := ethclientRpcClients[rpcClientKey]; len(networkClients) == 0 {
		rpcClient, err := EVMResolveJsonRpcClient(rpcClientKey, rpcURL)
		if err != nil {
			prvdcommon.Log.Warningf("Failed to dial JSON-RPC host: %s", rpcURL)
			return nil, err
		}
		client = ethclient.NewClient(rpcClient)
		evmMutex.Lock()
		ethrpcClients[rpcClientKey] = append(ethrpcClients[rpcClientKey], rpcClient)
		ethclientRpcClients[rpcClientKey] = append(networkClients, client)
		evmMutex.Unlock()
	} else {
		client = ethclientRpcClients[rpcClientKey][0]
	}

	_, err := EVMGetSyncProgress(client)
	if err != nil {
		evmClearCachedClients(rpcClientKey)
		return nil, err
	}

	return client, nil
}

// EVMInvokeJsonRpcClient - invokes the JSON-RPC client for the given network and url
func EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, method string, params []interface{}, response interface{}) error {
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		Timeout: rpcTimeout(),
	}
	id, err := uuid.NewV4()
	if err != nil {
		prvdcommon.Log.Warningf("Failed to generate UUID for JSON-RPC request; %s", err.Error())
		return err
	}
	payload := map[string]interface{}{
		"method":  method,
		"params":  params,
		"id":      id.String(),
		"jsonrpc": "2.0",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		prvdcommon.Log.Warningf("Failed to marshal JSON payload for %s JSON-RPC invocation; %s", method, err.Error())
		return err
	}
	resp, err := client.Post(rpcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		prvdcommon.Log.Warningf("Failed to invoke JSON-RPC method: %s; %s", method, err.Error())
		return err
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	err = json.Unmarshal(buf.Bytes(), response)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal %s JSON-RPC response: %s; %s", method, buf.Bytes(), err.Error())
	}
	prvdcommon.Log.Debugf("Invocation of JSON-RPC method %s succeeded (%v-byte response)", method, buf.Len())
	return nil
}

// EVMResolveEthClient resolves a cached *ethclient.Client client or dials and caches a new instance
func EVMResolveEthClient(rpcClientKey, rpcURL string) (*ethclient.Client, error) {
	var client *ethclient.Client
	if networkClients, _ := ethclientRpcClients[rpcClientKey]; len(networkClients) == 0 {
		client, err := EVMDialJsonRpc(rpcClientKey, rpcURL)
		if err != nil {
			prvdcommon.Log.Warningf("Failed to dial RPC client for JSON-RPC host: %s", rpcURL)
			return nil, err
		}
		evmMutex.Lock()
		ethclientRpcClients[rpcClientKey] = append(networkClients, client)
		evmMutex.Unlock()
	} else {
		client = ethclientRpcClients[rpcClientKey][0]
		prvdcommon.Log.Debugf("Resolved cached *ethclient.Client instance for JSON-RPC host @ %s", rpcURL)
	}
	return client, nil
}

// EVMResolveJsonRpcClient resolves a cached *ethclient.Client client or dials and caches a new instance
func EVMResolveJsonRpcClient(rpcClientKey, rpcURL string) (*ethrpc.Client, error) {
	var client *ethrpc.Client
	if networkClients, _ := ethrpcClients[rpcClientKey]; len(networkClients) == 0 {
		erpc, err := ethrpc.Dial(rpcURL)
		if err != nil {
			prvdcommon.Log.Warningf("Failed to dial RPC client for JSON-RPC host: %s", rpcURL)
			return nil, err
		}
		client = erpc
		evmMutex.Lock()
		ethrpcClients[rpcClientKey] = append(networkClients, client)
		evmMutex.Unlock()
	} else {
		client = ethrpcClients[rpcClientKey][0]
		prvdcommon.Log.Debugf("Resolved JSON-RPC host @ %s", rpcURL)
	}
	return client, nil
}

// EVMEncodeABI returns the ABI-encoded calldata for the given method and params
func EVMEncodeABI(method *abi.Method, params ...interface{}) ([]byte, error) {
	var methodDescriptor = fmt.Sprintf("method %s", method.Name)
	defer func() {
		if r := recover(); r != nil {
			prvdcommon.Log.Debugf("Failed to encode ABI-compliant calldata for method: %s", methodDescriptor)
		}
	}()

	prvdcommon.Log.Debugf("Attempting to encode %d parameters prior to executing contract method: %s", len(params), methodDescriptor)
	var args []interface{}

	for i := range params {
		if i >= len(method.Inputs) {
			break
		}
		input := method.Inputs[i]
		param := params[i]
		paramType := reflect.TypeOf(param).Kind()

		prvdcommon.Log.Debugf("Attempting to coerce encoding of %v abi parameter; value (%s): %s", input.Type, paramType, param)
		switch paramType {
		case reflect.Slice:
			if input.Type.GetType().Kind() == reflect.String {
				param = []byte(param.(string))
			}
		default:
			param, _ = coerceAbiParameter(input.Type, params[i])
		}

		args = append(args, param)
		prvdcommon.Log.Debugf("Coerced encoding of %s abi parameter; value: %s", input.Type.String(), param)
	}

	encodedArgs, err := method.Inputs.Pack(args...)
	if err != nil {
		return nil, err
	}

	prvdcommon.Log.Debugf("Encoded %v abi params prior to executing contract method: %s; abi-encoded arguments %v bytes packed", len(params), methodDescriptor, len(encodedArgs))
	return append(method.ID, encodedArgs...), nil
}

// EVMGenerateKeyPair - creates and returns an ECDSA keypair;
// the returned *ecdsa.PrivateKey can be encoded with: hex.EncodeToString(ethcrypto.FromECDSA(privateKey))
func EVMGenerateKeyPair() (address *string, privateKey *ecdsa.PrivateKey, err error) {
	privateKey, err = ethcrypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	address = prvdcommon.StringOrNil(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex())
	return address, privateKey, nil
}

// EVMMarshalKeyPairJSON - returns keystore JSON representation of given private key
func EVMMarshalKeyPairJSON(addr common.Address, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	type keyJSON struct {
		ID         string `json:"id"`
		Address    string `json:"address"`
		PrivateKey string `json:"privatekey"`
		Version    int    `json:"version"`
	}
	keyUUID, _ := generateEVMKeyUUID()
	key := keyJSON{
		ID:         keyUUID,
		Address:    hex.EncodeToString(addr[:]),
		PrivateKey: hex.EncodeToString(ethcrypto.FromECDSA(privateKey)),
		Version:    3,
	}
	return json.Marshal(key)
}

// EVMMarshalEncryptedKey encrypts key as version 3.
func EVMMarshalEncryptedKey(addr common.Address, privateKey *ecdsa.PrivateKey, secret string) ([]byte, error) {
	const (
		// n,r,p = 2^12, 8, 6 uses 4MB memory and approx 100ms CPU time on a modern CPU.
		LightScryptN = 1 << 12
		LightScryptP = 6

		scryptR     = 4
		scryptDKLen = 32
	)

	type cipherparamsJSON struct {
		IV string `json:"iv"`
	}

	type cryptoJSON struct {
		Cipher       string                 `json:"cipher"`
		CipherText   string                 `json:"ciphertext"`
		CipherParams cipherparamsJSON       `json:"cipherparams"`
		KDF          string                 `json:"kdf"`
		KDFParams    map[string]interface{} `json:"kdfparams"`
		MAC          string                 `json:"mac"`
	}

	type web3v3 struct {
		ID      string     `json:"id"`
		Address string     `json:"address"`
		Crypto  cryptoJSON `json:"crypto"`
		Version int        `json:"version"`
	}

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		prvdcommon.Log.Errorf("Failed while reading from crypto/rand; %s", err.Error())
		return nil, err
	}

	derivedKey, err := scrypt.Key([]byte(secret), salt, LightScryptN, scryptR, LightScryptP, scryptDKLen)
	if err != nil {
		return nil, err
	}
	encryptKey := derivedKey[:16]
	keyBytes := ethcrypto.FromECDSA(privateKey)

	iv := make([]byte, aes.BlockSize) // 16
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		prvdcommon.Log.Errorf("Failed while reading from crypto/rand; %s", err.Error())
		return nil, err
	}

	cipherText, err := aesCTRXOR(encryptKey, keyBytes, iv)
	if err != nil {
		return nil, err
	}
	mac := ethcrypto.Keccak256(derivedKey[16:32], cipherText)

	keyUUID, _ := generateEVMKeyUUID()

	return json.Marshal(web3v3{
		ID:      keyUUID,
		Address: hex.EncodeToString(addr[:]),
		Crypto: cryptoJSON{
			Cipher:     "aes-128-ctr",
			CipherText: hex.EncodeToString(cipherText),
			CipherParams: cipherparamsJSON{
				IV: hex.EncodeToString(iv),
			},
			KDF: "scrypt",
			KDFParams: map[string]interface{}{
				"n":     LightScryptN,
				"r":     scryptR,
				"p":     LightScryptP,
				"dklen": scryptDKLen,
				"salt":  hex.EncodeToString(salt),
			},
			MAC: hex.EncodeToString(mac),
		},
		Version: 3,
	})
}

func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	// AES-128 is selected due to size of encryptKey.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}

func generateEVMKeyUUID() (string, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return "", err
	}
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[:4], u[4:6], u[6:8], u[8:10], u[10:]), nil
}

// EVMHashFunctionSelector returns the first 4 bytes of the Keccak256 hash of the given function selector
func EVMHashFunctionSelector(sel string) string {
	hash := Keccak256(sel)
	return common.Bytes2Hex(hash[0:4])
}

// FromECDSA exports a private key into a binary dump.
func FromECDSA(priv *ecdsa.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}

// HexToAddress returns Address with byte values of s.
// If s is larger than len(h), s will be cropped from the left.
func HexToAddress(s string) common.Address {
	return common.BytesToAddress(common.FromHex(s))
}

// Keccak256 hash the given string
func Keccak256(str string) []byte {
	return ethcrypto.Keccak256([]byte(str))
}

// Transaction broadcast helpers

// EVMBroadcastTx injects a signed transaction into the pending pool for execution.
func EVMBroadcastTx(ctx context.Context, rpcClientKey, rpcURL string, tx *types.Transaction, client *ethclient.Client, result interface{}) error {
	rpcClient, err := EVMResolveJsonRpcClient(rpcClientKey, rpcURL)
	if err != nil {
		return err
	}

	data, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return err
	}

	return rpcClient.CallContext(ctx, result, "eth_sendRawTransaction", common.ToHex(data))
}

// EVMBroadcastSignedTx emits a given signed tx for inclusion in a block
func EVMBroadcastSignedTx(rpcClientKey, rpcURL string, signedTx *types.Transaction) error {
	client, err := EVMDialJsonRpc(rpcClientKey, rpcURL)
	if err != nil {
		return fmt.Errorf("Failed to dial JSON-RPC host; %s", err.Error())
	} else if signedTx != nil {
		prvdcommon.Log.Debugf("Transmitting signed tx to JSON-RPC host")
		err = EVMBroadcastTx(context.TODO(), rpcClientKey, rpcURL, signedTx, client, nil)
		if err != nil {
			return fmt.Errorf("Failed to transmit signed tx to JSON-RPC host; %s", err.Error())
		}
	}
	return nil
}

// EVMChainConfigFactory returns the chain config for the given chain id
func EVMChainConfigFactory(chainID *big.Int) *params.ChainConfig {
	switch chainID.Uint64() {
	case params.MainnetChainConfig.ChainID.Uint64():
		return params.MainnetChainConfig
	case params.RopstenChainConfig.ChainID.Uint64():
		return params.RopstenChainConfig
	case params.RinkebyChainConfig.ChainID.Uint64():
		return params.RinkebyChainConfig
	case params.GoerliChainConfig.ChainID.Uint64():
		return params.GoerliChainConfig
	case params.YoloV1ChainConfig.ChainID.Uint64():
		return params.YoloV1ChainConfig
	case kovanChainID: // HACK
		kovanConfig := params.GoerliChainConfig
		kovanConfig.ChainID = chainID
		return kovanConfig
	}

	return params.MainnetChainConfig
}

// EVMTxFactory builds and returns an unsigned transaction hash
func EVMTxFactory(
	rpcClientKey,
	rpcURL,
	from string,
	to,
	data *string,
	val *big.Int,
	nonce *uint64,
	gasLimit uint64,
	gasPrice *uint64,
) (types.Signer, *types.Transaction, []byte, error) {
	client, err := EVMDialJsonRpc(rpcClientKey, rpcURL)
	if err != nil {
		return nil, nil, nil, err
	}

	chainID, err := EVMGetChainID(rpcClientKey, rpcURL)
	if err != nil {
		return nil, nil, nil, err
	}

	block, err := EVMGetLatestBlockNumber(rpcClientKey, rpcURL)
	if err != nil {
		return nil, nil, nil, err
	}

	chainParams := EVMChainConfigFactory(chainID)
	signer := types.MakeSigner(chainParams, big.NewInt(int64(block)))

	if nonce == nil {
		pendingNonce, err := client.PendingNonceAt(context.TODO(), common.HexToAddress(from))
		if err != nil {
			prvdcommon.Log.Warningf("failed to retrieve next nonce; %s", err.Error())
			return nil, nil, nil, err
		}
		if pendingNonce == 0 {
			pendingNonce, err = client.NonceAt(context.TODO(), common.HexToAddress(from), nil)
			if err != nil {
				prvdcommon.Log.Warningf("failed to retrieve next nonce; %s", err.Error())
				return nil, nil, nil, err
			}
		}
		// if err != nil || pendingNonce == 0 {
		// 	// check to make sure this isn't parity
		// 	var jsonRPCResponse = &api.EthereumJsonRpcResponse{}
		// 	err := EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, "parity_nextNonce", []interface{}{from}, &jsonRPCResponse)
		// 	if err != nil {
		// 		prvdcommon.Log.Warningf("failed to retrieve next nonce; %s", err.Error())
		// 		return nil, nil, nil, err
		// 	}
		// 	if jsonRPCResponse.Result != nil {
		// 		pendingNonce, err = hexutil.DecodeUint64(jsonRPCResponse.Result.(string))
		// 		if err != nil {
		// 			prvdcommon.Log.Warningf("failed to decode next nonce; %s", err.Error())
		// 			return nil, nil, nil, err
		// 		}
		// 	} else {
		// 		prvdcommon.Log.Warningf("failed to retrieve next nonce; JSON-RPC result was nil")
		// 	}
		// }
		nonce = &pendingNonce
	}

	if gasPrice == nil {
		suggestedGasPrice, err := client.SuggestGasPrice(context.TODO())
		if err != nil {
			prvdcommon.Log.Warningf("failed to suggest gas price; %s", err.Error())
			return nil, nil, nil, err
		}
		_gasPrice := suggestedGasPrice.Uint64()
		gasPrice = &_gasPrice
	}

	var _data []byte
	if data != nil {
		_data = common.FromHex(*data)
	}

	var tx *types.Transaction

	if gasLimit == 0 {
		gasLimit, err = client.EstimateGas(context.TODO(), asEVMCallMsg(
			from,
			_data,
			to,
			val,
			*gasPrice,
			gasLimit,
		))
		if err != nil {
			prvdcommon.Log.Warningf("failed to estimate gas for tx; %s", err.Error())
			return nil, nil, nil, err
		}
		prvdcommon.Log.Debugf("estimated gas for %d-byte tx: %d", len(_data), gasLimit)
	}

	// check account balance
	if gasLimit > 0 {
		balance, err := client.BalanceAt(context.TODO(), common.HexToAddress(from), nil)
		if err != nil {
			return nil, nil, nil, err
		}
		// cost = gaslimit * gasprice
		limit := new(big.Int).SetUint64(gasLimit)
		price := new(big.Int).SetUint64(*gasPrice)
		cost := new(big.Int)
		cost = cost.Mul(limit, price)
		// compare the balance to the cost
		cmp := balance.Cmp(cost)
		if cmp == -1 {
			// there is not enough wei in the account to pay for the transaction (balance < gaslimit)
			return nil, nil, nil, fmt.Errorf("insufficient balance in account")
		}
	}

	if to != nil {
		addr := common.HexToAddress(*to)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to estimate gas for tx; %s", err.Error())
		}
		prvdcommon.Log.Debugf("estimated %d total gas required for tx with %d-byte data payload", gasLimit, len(_data))
		tx = types.NewTransaction(*nonce, addr, val, gasLimit, big.NewInt(int64(*gasPrice)), _data)
	} else {
		prvdcommon.Log.Debugf("attempting to deploy contract via tx; network: %s", rpcClientKey)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to estimate gas for tx; %s", err.Error())
		}
		prvdcommon.Log.Debugf("estimated %d total gas required for contract deployment tx with %d-byte data payload", gasLimit, len(_data))
		tx = types.NewContractCreation(*nonce, val, gasLimit, big.NewInt(int64(*gasPrice)), _data)
	}

	hash := signer.Hash(tx).Bytes()
	return signer, tx, hash, err
}

// EVMSignTx signs a transaction using the given private key and calldata;
// providing 0 gas results in the tx attempting to use up to the block
// gas limit for execution
func EVMSignTx(
	rpcClientKey,
	rpcURL,
	from,
	privateKey string,
	to,
	data *string,
	val *big.Int,
	nonce *uint64,
	gasLimit uint64,
	gasPrice *uint64,
) (*types.Transaction, *string, error) {
	signer, tx, hash, err := EVMTxFactory(
		rpcClientKey,
		rpcURL,
		from,
		to,
		data,
		val,
		nonce,
		gasLimit,
		gasPrice,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("failed read private key bytes prior to signing tx; %s", err.Error())
	}

	prvdcommon.Log.Debugf("signing tx on behalf of %s", from)
	_privateKey, err := ethcrypto.HexToECDSA(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed read private key bytes prior to signing tx; %s", err.Error())
	}

	sig, err := ethcrypto.Sign(hash, _privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign tx on behalf of %s; %s", *to, err.Error())
	}

	signedTx, _ := tx.WithSignature(signer, sig)
	signedTxJSON, _ := signedTx.MarshalJSON()

	prvdcommon.Log.Debugf("signed eth tx: %s", signedTxJSON)
	return signedTx, prvdcommon.StringOrNil(fmt.Sprintf("0x%x", signedTx.Hash())), nil
}

// ABI-related helpers

func coerceAbiParameter(t abi.Type, v interface{}) (interface{}, error) {
	typestr := fmt.Sprintf("%s", t)
	defer func() {
		if r := recover(); r != nil {
			prvdcommon.Log.Debugf("failed to coerce ABI parameter of type: %s; value: %s", typestr, v)
		}
	}()
	switch t.T {
	case abi.ArrayTy, abi.SliceTy:
		switch v.(type) {
		case []byte:
			return evmForEachUnpack(t, v.([]byte), 0, len(v.([]interface{}))-1)
		case string:
			return evmForEachUnpack(t, []byte(v.(string)), 0, len(v.(string)))
		default:
			// HACK-- this fallback for edge case handling isn't the cleanest
			if typestr == "uint256[]" {
				prvdcommon.Log.Debugf("Attempting fallback coercion of uint256[] abi parameter")
				vals := make([]*big.Int, t.Size)
				for _, val := range v.([]interface{}) {
					vals = append(vals, big.NewInt(int64(val.(float64))))
				}
				return vals, nil
			}
		}
	case abi.StringTy: // variable arrays are written at the end of the return bytes
		if val, valOk := v.(string); valOk {
			return val, nil
		}
		return string(v.([]byte)), nil
	case abi.IntTy, abi.UintTy:
		switch t.GetType().Kind() {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			var intval *big.Int
			if valInt64, valInt64Ok := v.(int64); valInt64Ok {
				intval = big.NewInt(int64(valInt64))
			} else if valFloat64, valFloat64Ok := v.(float64); valFloat64Ok {
				intval = big.NewInt(int64(valFloat64))
			}
			if intval != nil {
				return evmReadInteger(t.GetType().Kind(), intval.Bytes()), nil
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if val, valOk := v.(string); valOk {
				intval, err := strconv.Atoi(val)
				if err != nil {
					prvdcommon.Log.Warningf("failed to coerce string val %s to integer type in accordance with abi; %s", v, err.Error())
					return nil, err
				}
				return big.NewInt(int64(intval)), nil
			}
			return big.NewInt(int64(v.(int64))), nil
		case reflect.Float64:
			return big.NewInt(int64(v.(float64))), nil
		case reflect.Ptr:
			switch v.(type) {
			case float64:
				return big.NewInt(int64(v.(float64))), nil
			}
		default:
			return evmReadInteger(t.GetType().Kind(), v.([]byte)), nil
		}
	case abi.BoolTy:
		if boolstr, ok := v.(string); ok {
			if strings.ToLower(boolstr) == "true" {
				return true, nil
			}
			return false, nil
		}
		return v.(bool), nil
	case abi.AddressTy:
		switch v.(type) {
		case string:
			return common.HexToAddress(v.(string)), nil
		default:
			return common.BytesToAddress(v.([]byte)), nil
		}
	case abi.HashTy:
		return common.BytesToHash(v.([]byte)), nil
	case abi.BytesTy:
		switch v.(type) {
		case string:
			return []byte(v.(string)), nil
		default:
			return v.([]byte), nil
		}
	case abi.FixedBytesTy:
		switch v.(type) {
		case string:
			return evmReadFixedBytes(t, []byte(v.(string)))
		default:
			return evmReadFixedBytes(t, v.([]byte))
		}
	case abi.FunctionTy:
		return evmReadFunctionType(t, v.([]byte))
	default:
		// no-op
	}
	return nil, fmt.Errorf("failed to coerce %s parameter for abi encoding; unhandled type: %v", t.String(), t)
}

// iteratively unpack elements
func evmForEachUnpack(t abi.Type, output []byte, start, size int) (interface{}, error) {
	if size < 0 {
		return nil, fmt.Errorf("cannot marshal input to array, size is negative (%d)", size)
	}
	if start+32*size > len(output) {
		return nil, fmt.Errorf("abi: cannot marshal in to go array: offset %d would go over slice boundary (len=%d)", len(output), start+32*size)
	}

	// this value will become our slice or our array, depending on the type
	var refSlice reflect.Value

	if t.T == abi.SliceTy {
		// declare our slice
		refSlice = reflect.MakeSlice(t.GetType(), size, size)
	} else if t.T == abi.ArrayTy {
		// declare our array
		refSlice = reflect.New(t.GetType()).Elem()
	} else {
		return nil, fmt.Errorf("abi: invalid type in array/slice unpacking stage")
	}

	// Arrays have packed elements, resulting in longer unpack steps.
	// Slices have just 32 bytes per element (pointing to the contents).
	elemSize := 32
	if t.T == abi.ArrayTy {
		elemSize = evmGetFullElemSize(t.Elem)
	}

	for i, j := start, 0; j < size; i, j = i+elemSize, j+1 {
		inter, err := coerceAbiParameter(t, output)
		if err != nil {
			return nil, err
		}

		// append the item to our reflect slice
		refSlice.Index(j).Set(reflect.ValueOf(inter))
	}

	// return the interface
	return refSlice.Interface(), nil
}

// reads the integer based on its kind
func evmReadInteger(kind reflect.Kind, b []byte) interface{} {
	switch kind {
	case reflect.Uint8:
		return b[len(b)-1]
	case reflect.Uint16:
		return binary.BigEndian.Uint16(b[len(b)-2:])
	case reflect.Uint32:
		return binary.BigEndian.Uint32(b[len(b)-4:])
	case reflect.Uint64:
		return binary.BigEndian.Uint64(b[len(b)-8:])
	case reflect.Int8:
		return int8(b[len(b)-1])
	case reflect.Int16:
		return int16(binary.BigEndian.Uint16(b[len(b)-2:]))
	case reflect.Int32:
		return int32(binary.BigEndian.Uint32(b[len(b)-4:]))
	case reflect.Int64:
		return int64(binary.BigEndian.Uint64(b[len(b)-8:]))
	default:
		return new(big.Int).SetBytes(b)
	}
}

// A function type is simply the address with the function selection signature at the end.
// This enforces that standard by always presenting it as a 24-array (address + sig = 24 bytes)
func evmReadFunctionType(t abi.Type, word []byte) (funcTy [24]byte, err error) {
	if t.T != abi.FunctionTy {
		return [24]byte{}, fmt.Errorf("abi: invalid type in call to make function type byte array")
	}
	if garbage := binary.BigEndian.Uint64(word[24:32]); garbage != 0 {
		err = fmt.Errorf("abi: got improperly encoded function type, got %v", word)
	} else {
		copy(funcTy[:], word[0:24])
	}
	return
}

// through reflection, creates a fixed array to be read from
func evmReadFixedBytes(t abi.Type, word []byte) (interface{}, error) {
	if t.T != abi.FixedBytesTy {
		return nil, fmt.Errorf("abi: invalid type in call to make fixed byte array")
	}

	prvdcommon.Log.Debugf("Attempting to read fixed bytes in accordance with Ethereum contract ABI; type: %v; word: %s", t, word)

	// convert
	array := reflect.New(t.GetType()).Elem()
	reflect.Copy(array, reflect.ValueOf(word))
	return array.Interface(), nil
}

func evmRequiresLengthPrefix(t *abi.Type) bool {
	return t.T == abi.StringTy || t.T == abi.BytesTy || t.T == abi.SliceTy
}

func evmGetFullElemSize(elem *abi.Type) int {
	//all other should be counted as 32 (slices have pointers to respective elements)
	size := 32
	//arrays wrap it, each element being the same size
	for elem.T == abi.ArrayTy {
		size *= elem.Size
		elem = elem.Elem
	}
	return size
}

func evmLengthPrefixPointsTo(index int, output []byte) (start int, length int, err error) {
	bigOffsetEnd := big.NewInt(0).SetBytes(output[index : index+32])
	bigOffsetEnd.Add(bigOffsetEnd, common.Big32)
	outputLength := big.NewInt(int64(len(output)))

	if bigOffsetEnd.Cmp(outputLength) > 0 {
		return 0, 0, fmt.Errorf("abi: cannot marshal in to go slice: offset %v would go over slice boundary (len=%v)", bigOffsetEnd, outputLength)
	}

	if bigOffsetEnd.BitLen() > 63 {
		return 0, 0, fmt.Errorf("abi offset larger than int64: %v", bigOffsetEnd)
	}

	offsetEnd := int(bigOffsetEnd.Uint64())
	lengthBig := big.NewInt(0).SetBytes(output[offsetEnd-32 : offsetEnd])

	totalSize := big.NewInt(0)
	totalSize.Add(totalSize, bigOffsetEnd)
	totalSize.Add(totalSize, lengthBig)
	if totalSize.BitLen() > 63 {
		return 0, 0, fmt.Errorf("abi length larger than int64: %v", totalSize)
	}

	if totalSize.Cmp(outputLength) > 0 {
		return 0, 0, fmt.Errorf("abi: cannot marshal in to go type: length insufficient %v require %v", outputLength, totalSize)
	}
	start = int(bigOffsetEnd.Uint64())
	length = int(lengthBig.Uint64())
	return
}

func evmReadBool(word []byte) (bool, error) {
	for _, b := range word[:31] {
		if b != 0 {
			return false, errors.New("abi: improperly encoded boolean value")
		}
	}
	switch word[31] {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("abi: improperly encoded boolean value")
	}
}

// More calldata construction related items

func asEVMCallMsg(
	from string,
	data []byte,
	to *string,
	val *big.Int,
	gasPrice,
	gasLimit uint64,
) ethereum.CallMsg {
	var _to *common.Address
	if to != nil {
		addr := common.HexToAddress(*to)
		_to = &addr
	}
	return ethereum.CallMsg{
		From:     common.HexToAddress(from),
		To:       _to,
		Gas:      gasLimit,
		GasPrice: big.NewInt(int64(gasPrice)),
		Value:    val,
		Data:     data,
	}
}

func parseContractABI(contractAbi interface{}) (*abi.ABI, error) {
	abistr, err := json.Marshal(contractAbi)
	if err != nil {
		prvdcommon.Log.Warningf("failed to marshal ABI from contract params to json; %s", err.Error())
		return nil, err
	}

	abival, err := abi.JSON(strings.NewReader(string(abistr)))
	if err != nil {
		prvdcommon.Log.Warningf("failed to initialize ABI from contract  params to json; %s", err.Error())
		return nil, err
	}

	return &abival, nil
}

// EVMEthCall invokes eth_call manually via JSON-RPC
func EVMEthCall(rpcClientKey, rpcURL string, params []interface{}) (*api.EthereumJsonRpcResponse, error) {
	var jsonRPCResponse = &api.EthereumJsonRpcResponse{}
	err := EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, "eth_call", params, &jsonRPCResponse)
	return jsonRPCResponse, err
}

// EVMGetBlockNumber retrieves the latest block known to the JSON-RPC client
func EVMGetBlockNumber(rpcClientKey, rpcURL string) *uint64 {
	params := make([]interface{}, 0)
	var resp = &api.EthereumJsonRpcResponse{}
	prvdcommon.Log.Debugf("attempting to fetch latest block number via JSON-RPC eth_blockNumber method")
	err := EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, "eth_blockNumber", params, &resp)
	if err != nil {
		prvdcommon.Log.Warningf("failed to invoke eth_blockNumber method via JSON-RPC; %s", err.Error())
		return nil
	}
	blockNumber, err := hexutil.DecodeBig(resp.Result.(string))
	if err != nil {
		return nil
	}
	_blockNumber := blockNumber.Uint64()
	return &_blockNumber
}

// EVMGetChainConfig parses the cached network config mapped to the given
// `rpcClientKey`, if one exists; otherwise, the mainnet chain config is returned.
func EVMGetChainConfig(rpcClientKey, rpcURL string) (*params.ChainConfig, error) {
	if cfg, ok := chainConfigs[rpcClientKey]; ok {
		return cfg, nil
	}
	cfg := params.MainnetChainConfig
	chainID, err := strconv.ParseUint(rpcClientKey, 10, 64)
	if err == nil {
		cfg.ChainID = big.NewInt(int64(chainID))
		chainConfigs[rpcClientKey] = cfg
	} else {
		cfg.ChainID, err = EVMGetChainID(rpcClientKey, rpcURL)
		if err != nil {
			return nil, fmt.Errorf("Error getting chain id. Error: %s", err.Error())
		}
	}
	return cfg, nil
}

// EVMGetChainID retrieves the current chainID via JSON-RPC
func EVMGetChainID(rpcClientKey, rpcURL string) (*big.Int, error) {
	ethClient, err := EVMDialJsonRpc(rpcClientKey, rpcURL)
	if err != nil {
		errmsg := fmt.Sprintf("Failed to obtain network id for *ethclient.Client instance with RPC URL: %s; %s", rpcURL, err.Error())
		prvdcommon.Log.Warningf(errmsg)
		return nil, fmt.Errorf(errmsg)
	}
	if ethClient == nil {
		errmsg := fmt.Sprintf("failed to read network id for unresolved *ethclient.Client instance; network id: %s; JSON-RPC URL: %s", rpcClientKey, rpcURL)
		prvdcommon.Log.Warningf(errmsg)
		return nil, fmt.Errorf(errmsg)
	}
	chainID, err := ethClient.NetworkID(context.TODO())
	if err != nil {
		errmsg := fmt.Sprintf("failed to read chain id for *ethclient.Client instance with RPC URL: %s; %s", rpcURL, err.Error())
		prvdcommon.Log.Warningf(errmsg)
		return nil, fmt.Errorf(errmsg)
	}
	if chainID != nil {
		prvdcommon.Log.Debugf("received chain id from *ethclient.Client instance with RPC URL: %s; %s", rpcURL, chainID)
	}
	return chainID, nil
}

// EVMGetGasPrice returns the gas price
func EVMGetGasPrice(rpcClientKey, rpcURL string) *string {
	params := make([]interface{}, 0)
	var resp = &api.EthereumJsonRpcResponse{}
	prvdcommon.Log.Debugf("Attempting to fetch gas price via JSON-RPC eth_gasPrice method")
	err := EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, "eth_gasPrice", params, &resp)
	if err != nil {
		prvdcommon.Log.Warningf("Failed to invoke eth_gasPrice method via JSON-RPC; %s", err.Error())
		return nil
	}
	return prvdcommon.StringOrNil(resp.Result.(string))
}

// EVMGetLatestBlock retrieves the latsest block
func EVMGetLatestBlock(rpcClientKey, rpcURL string) (*api.EthereumJsonRpcResponse, error) {
	var jsonRPCResponse = &api.EthereumJsonRpcResponse{}
	err := EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, "eth_getBlockByNumber", []interface{}{"latest", true}, &jsonRPCResponse)
	return jsonRPCResponse, err
}

// EVMGetLatestBlockNumber retrieves the latest block number
func EVMGetLatestBlockNumber(rpcClientKey, rpcURL string) (uint64, error) {
	resp, err := EVMGetLatestBlock(rpcClientKey, rpcURL)
	if err != nil {
		return 0, err
	}
	blockNumberStr, blockNumberStrOk := resp.Result.(map[string]interface{})["number"].(string)
	if !blockNumberStrOk {
		return 0, errors.New("Unable to parse block number from JSON-RPC response")
	}
	blockNumber, err := hexutil.DecodeUint64(blockNumberStr)
	if err != nil {
		return 0, fmt.Errorf("Unable to decode block number hex; %s", err.Error())
	}
	return blockNumber, nil
}

// EVMGetBlockGasLimit retrieves the latest block gas limit
func EVMGetBlockGasLimit(rpcClientKey, rpcURL string) (uint64, error) {
	resp, err := EVMGetLatestBlock(rpcClientKey, rpcURL)
	if err != nil {
		return 0, err
	}
	blockGasLimitStr, blockGasLimitStrOk := resp.Result.(map[string]interface{})["gasLimit"].(string)
	if !blockGasLimitStrOk {
		return 0, errors.New("Unable to parse block gas limit from JSON-RPC response")
	}
	blockGasLimit, err := hexutil.DecodeUint64(blockGasLimitStr)
	if err != nil {
		return 0, fmt.Errorf("Unable to decode block gas limit hex; %s", err.Error())
	}
	return blockGasLimit, nil
}

// EVMGetBlockByNumber retrieves a given block by number
func EVMGetBlockByNumber(rpcClientKey, rpcURL string, blockNumber uint64) (*api.EthereumJsonRpcResponse, error) {
	var jsonRPCResponse = &api.EthereumJsonRpcResponse{}
	err := EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, "eth_getBlockByNumber", []interface{}{hexutil.EncodeUint64(blockNumber), true}, &jsonRPCResponse)
	return jsonRPCResponse, err
}

// EVMGetHeaderByNumber retrieves a given block header by number
func EVMGetHeaderByNumber(rpcClientKey, rpcURL string, blockNumber uint64) (*api.EthereumJsonRpcResponse, error) {
	var jsonRPCResponse = &api.EthereumJsonRpcResponse{}
	err := EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, "eth_getHeaderByNumber", []interface{}{hexutil.EncodeUint64(blockNumber), true}, &jsonRPCResponse)
	return jsonRPCResponse, err
}

// EVMGetNativeBalance retrieves a wallet's native currency balance
func EVMGetNativeBalance(rpcClientKey, rpcURL, addr string) (*big.Int, error) {
	client, err := EVMDialJsonRpc(rpcClientKey, rpcURL)
	if err != nil {
		return nil, err
	}
	return client.BalanceAt(context.TODO(), common.HexToAddress(addr), nil)
}

// EVMGetNetworkStatus retrieves current metadata from the JSON-RPC client;
// returned struct includes block height, chainID, number of connected peers,
// protocol version, and syncing state.
func EVMGetNetworkStatus(rpcClientKey, rpcURL string) (*api.NetworkStatus, error) {
	ethClient, err := EVMDialJsonRpc(rpcClientKey, rpcURL)
	if err != nil || rpcURL == "" || ethClient == nil {
		meta := map[string]interface{}{
			"error": nil,
		}
		if err != nil {
			prvdcommon.Log.Warningf("Failed to dial JSON-RPC host: %s; %s", rpcURL, err.Error())
			meta["error"] = err.Error()
		} else if rpcURL == "" {
			meta["error"] = "No 'full-node' JSON-RPC URL configured or resolvable"
		} else if ethClient == nil {
			meta["error"] = "Configured 'full-node' JSON-RPC client not resolved"
		}
		return &api.NetworkStatus{
			State: prvdcommon.StringOrNil("configuring"),
			Meta:  meta,
		}, nil
	}

	defer func() {
		if r := recover(); r != nil {
			prvdcommon.Log.Debugf("Recovered from failed attempt to retrieve network sync progress from JSON-RPC host: %s", rpcURL)
			evmClearCachedClients(rpcClientKey)
		}
	}()

	syncProgress, err := EVMGetSyncProgress(ethClient)
	if err != nil {
		prvdcommon.Log.Warningf("Failed to read network sync progress using JSON-RPC host; %s", err.Error())
		evmClearCachedClients(rpcClientKey)
		return nil, err
	}
	var state string
	var block uint64        // current block; will be less than height while syncing in progress
	var height *uint64      // total number of blocks
	var lastBlockAt *uint64 // unix timestamp of last block
	chainID, err := EVMGetChainID(rpcClientKey, rpcURL)
	if err != nil {
		return nil, err
	}
	peers := EVMGetPeerCount(rpcClientKey, rpcURL)
	protocolVersion := EVMGetProtocolVersion(rpcClientKey, rpcURL)
	meta := map[string]interface{}{}
	var syncing = false
	if syncProgress == nil {
		state = "synced"
		resp, err := EVMGetLatestBlock(rpcClientKey, rpcURL)
		if err != nil {
			prvdcommon.Log.Warningf("Failed to read latest block for %s using JSON-RPC host; %s", rpcURL, err.Error())
			return nil, err
		}
		hdr := resp.Result.(map[string]interface{})
		delete(hdr, "transactions") // HACK
		delete(hdr, "uncles")       // HACK

		meta["last_block_header"] = hdr
		block, err = hexutil.DecodeUint64(hdr["number"].(string))
		if err != nil {
			return nil, fmt.Errorf("Unable to decode block number hex; %s", err.Error())
		}

		_lastBlockAt, err := hexutil.DecodeUint64(hdr["timestamp"].(string))
		if err != nil {
			return nil, fmt.Errorf("Unable to decode block timestamp hex; %s", err.Error())
		}
		lastBlockAt = &_lastBlockAt
	} else {
		block = syncProgress.CurrentBlock
		height = &syncProgress.HighestBlock
		syncing = true
	}
	return &api.NetworkStatus{
		Block:           block,
		Height:          height,
		ChainID:         prvdcommon.StringOrNil(hexutil.EncodeBig(chainID)),
		PeerCount:       peers,
		LastBlockAt:     lastBlockAt,
		ProtocolVersion: protocolVersion,
		State:           prvdcommon.StringOrNil(state),
		Syncing:         syncing,
		Meta:            meta,
	}, nil
}

// EVMGetPeerCount returns the number of peers currently connected to the JSON-RPC client
func EVMGetPeerCount(rpcClientKey, rpcURL string) uint64 {
	var peerCount uint64
	params := make([]interface{}, 0)
	var resp = &api.EthereumJsonRpcResponse{}
	prvdcommon.Log.Debugf("Attempting to fetch peer count via net_peerCount method via JSON-RPC")
	err := EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, "net_peerCount", params, &resp)
	if err != nil {
		prvdcommon.Log.Debugf("Attempting to fetch peer count via parity_netPeers method via JSON-RPC")
		err := EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, "parity_netPeers", params, &resp)
		prvdcommon.Log.Warningf("Failed to invoke parity_netPeers method via JSON-RPC; %s", err.Error())
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

// EVMGetProtocolVersion returns the JSON-RPC client protocol version
func EVMGetProtocolVersion(rpcClientKey, rpcURL string) *string {
	params := make([]interface{}, 0)
	var resp = &api.EthereumJsonRpcResponse{}
	prvdcommon.Log.Debugf("Attempting to fetch protocol version via JSON-RPC eth_protocolVersion method")
	err := EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, "eth_protocolVersion", params, &resp)
	if err != nil {
		prvdcommon.Log.Debugf("Attempting to fetch protocol version via JSON-RPC net_version method")
		err := EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, "net_version", params, &resp)

		prvdcommon.Log.Warningf("Failed to invoke eth_protocolVersion method via JSON-RPC; %s", err.Error())
		return nil
	}
	return prvdcommon.StringOrNil(resp.Result.(string))
}

// EVMGetCode retrieves the code stored at the named address in the given scope;
// scope can be a block number, latest, earliest or pending
func EVMGetCode(rpcClientKey, rpcURL, addr, scope string) (*string, error) {
	params := make([]interface{}, 0)
	params = append(params, addr)
	params = append(params, scope)
	var resp = &api.EthereumJsonRpcResponse{}
	prvdcommon.Log.Debugf("Attempting to fetch code from %s via eth_getCode JSON-RPC method", addr)
	err := EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, "eth_getCode", params, &resp)
	if err != nil {
		prvdcommon.Log.Warningf("Failed to invoke eth_getCode method via JSON-RPC; %s", err.Error())
		return nil, err
	}
	return prvdcommon.StringOrNil(resp.Result.(string)), nil
}

// EVMGetSyncProgress retrieves the status of the current network sync
func EVMGetSyncProgress(client *ethclient.Client) (*ethereum.SyncProgress, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), evmSyncTimeout())
	progress, err := client.SyncProgress(ctx)
	if err != nil {
		prvdcommon.Log.Warningf("Error obtaining sync progress for *ethclient.Client instance; %s", err.Error())
		cancel()
		return nil, err
	}
	if progress != nil {
		prvdcommon.Log.Debugf("Latest synced block reported by *ethclient.Client instance [%v of %v]", progress.CurrentBlock, progress.HighestBlock)
	}
	cancel()
	return progress, nil
}

// EVMGetTokenBalance retrieves a token balance for a specific token contract and network address
func EVMGetTokenBalance(rpcClientKey, rpcURL, tokenAddr, addr string, contractABI interface{}) (*big.Int, error) {
	var balance *big.Int
	abi, err := parseContractABI(contractABI)
	if err != nil {
		return nil, err
	}
	client, err := EVMDialJsonRpc(rpcClientKey, rpcURL)
	gasPrice, _ := client.SuggestGasPrice(context.TODO())
	to := common.HexToAddress(tokenAddr)
	msg := ethereum.CallMsg{
		From:     common.HexToAddress(addr),
		To:       &to,
		Gas:      0,
		GasPrice: gasPrice,
		Value:    nil,
		Data:     common.FromHex(EVMHashFunctionSelector("balanceOf(address)")),
	}
	result, _ := client.CallContract(context.TODO(), msg, nil)
	if method, ok := abi.Methods["balanceOf"]; ok {
		method.Outputs.Unpack(&balance, result)
		if balance != nil {
			symbol, _ := EVMGetTokenSymbol(rpcClientKey, rpcURL, addr, tokenAddr, contractABI)
			if symbol != nil {
				prvdcommon.Log.Debugf("Read %s token balance (%v) from token contract address: %s", *symbol, balance, addr)
			}
		}
	} else {
		prvdcommon.Log.Warningf("Unable to read balance of unsupported token contract address: %s", tokenAddr)
	}
	return balance, nil
}

// EVMGetTokenSymbol attempts to retrieve the symbol of a token presumed to be deployed at the given token contract address
func EVMGetTokenSymbol(rpcClientKey, rpcURL, from, tokenAddr string, contractABI interface{}) (*string, error) {
	client, err := EVMDialJsonRpc(rpcClientKey, rpcURL)
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
		Data:     common.FromHex(EVMHashFunctionSelector("symbol()")),
	}
	result, _ := client.CallContract(context.TODO(), msg, nil)
	var symbol string
	if method, ok := _abi.Methods["symbol"]; ok {
		err = method.Outputs.Unpack(&symbol, result)
		if err != nil {
			prvdcommon.Log.Warningf("Failed to read token symbol from deployed token contract %s; %s", tokenAddr, err.Error())
		}
	}
	return prvdcommon.StringOrNil(symbol), nil
}

// EVMTraceTx returns the VM traces; requires parity JSON-RPC client and the node must
// be configured with `--fat-db on --tracing on --pruning archive`
func EVMTraceTx(rpcClientKey, rpcURL string, hash *string) (interface{}, error) {
	var addr = *hash
	if !strings.HasPrefix(addr, "0x") {
		addr = fmt.Sprintf("0x%s", addr)
	}
	params := make([]interface{}, 0)
	params = append(params, addr)
	var result = &api.EthereumTxTraceResponse{}
	prvdcommon.Log.Debugf("Attempting to trace tx via trace_transaction method via JSON-RPC; tx hash: %s", addr)
	err := EVMInvokeJsonRpcClient(rpcClientKey, rpcURL, "trace_transaction", params, &result)
	if err != nil {
		prvdcommon.Log.Warningf("Failed to invoke trace_transaction method via JSON-RPC; %s", err.Error())
		return nil, err
	}
	return result, nil
}

// EVMGetTxReceipt retrieves the full transaction receipt via JSON-RPC given the transaction hash
func EVMGetTxReceipt(rpcClientKey, rpcURL, txHash, from string) (*types.Receipt, error) {
	client, err := EVMDialJsonRpc(rpcClientKey, rpcURL)
	if err != nil {
		prvdcommon.Log.Warningf("Failed to retrieve tx receipt for broadcast tx: %s; %s", txHash, err.Error())
		return nil, err
	}
	prvdcommon.Log.Debugf("Attempting to retrieve tx receipt for broadcast tx: %s", txHash)
	return client.TransactionReceipt(context.TODO(), common.HexToHash(txHash))
}
