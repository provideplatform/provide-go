package provide

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
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/randentropy"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	ethrpc "github.com/ethereum/go-ethereum/rpc"
)

// The purpose of this class is to expose generic transactional and ABI-related helper
// methods; ethereum.go is a convenience wrapper around JSON-RPC.

// It also caches JSON-RPC client instances in a few flavors (*ethclient.Client and *ethrpc.Client)
// and maps them to an arbitrary `networkID` after successfully dialing the given RPC URL.

var chainConfigs = map[string]*params.ChainConfig{}        // mapping of network ids to *params.ChainConfig
var ethclientRpcClients = map[string][]*ethclient.Client{} // mapping of network ids to *ethclient.Client instances
var ethrpcClients = map[string][]*ethrpc.Client{}          // mapping of network ids to *ethrpc.Client instances

// DialJsonRpc - dials and caches a new JSON-RPC client instance at the JSON-RPC url and caches it using the given network id
func DialJsonRpc(networkID, rpcURL string) (*ethclient.Client, error) {
	var client *ethclient.Client

	if networkClients, _ := ethclientRpcClients[networkID]; len(networkClients) == 0 {
		rpcClient, err := ResolveJsonRpcClient(networkID, rpcURL)
		ethrpcClients[networkID] = append(ethrpcClients[networkID], rpcClient)
		if err != nil {
			Log.Warningf("Failed to dial JSON-RPC host: %s", rpcURL)
			return nil, err
		}
		client = ethclient.NewClient(rpcClient)
		ethclientRpcClients[networkID] = append(networkClients, client)
		Log.Debugf("Dialed JSON-RPC host @ %s", rpcURL)
	} else {
		client = ethclientRpcClients[networkID][0]
	}

	_, err := GetSyncProgress(client)
	if err != nil {
		Log.Warningf("Failed to read sync progress for *ethclient.Client instance: %s; %s", client, err.Error())
		return nil, err
	}

	return client, nil
}

// InvokeJsonRpcClient - invokes the JSON-RPC client for the given network and url
func InvokeJsonRpcClient(networkID, rpcURL, method string, params []interface{}, response interface{}) error {
	client := &http.Client{
		Transport: &http.Transport{}, // FIXME-- support self-signed certs here
		Timeout:   time.Second * 60,
	}
	payload := map[string]interface{}{
		"method":  method,
		"params":  params,
		"id":      GetChainID(networkID, rpcURL),
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
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	err = json.Unmarshal(buf.Bytes(), response)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal %s JSON-RPC response: %s; %s", method, buf.Bytes(), err.Error())
	}
	Log.Debugf("Invocation of JSON-RPC method %s succeeded (%v-byte response)", method, buf.Len())
	return nil
}

// ResolveEthClient resolves a cached *ethclient.Client client or dials and caches a new instance
func ResolveEthClient(networkID, rpcURL string) (*ethclient.Client, error) {
	var client *ethclient.Client
	if networkClients, _ := ethclientRpcClients[networkID]; len(networkClients) == 0 {
		client, err := DialJsonRpc(networkID, rpcURL)
		if err != nil {
			Log.Warningf("Failed to dial RPC client for JSON-RPC host: %s", rpcURL)
			return nil, err
		}
		ethclientRpcClients[networkID] = append(networkClients, client)
		Log.Debugf("Dialed JSON-RPC host @ %s", rpcURL)
	} else {
		client = ethclientRpcClients[networkID][0]
		Log.Debugf("Resolved cached *ethclient.Client instance for JSON-RPC host @ %s", rpcURL)
	}
	return client, nil
}

// ResolveJsonRpcClient resolves a cached *ethclient.Client client or dials and caches a new instance
func ResolveJsonRpcClient(networkID, rpcURL string) (*ethrpc.Client, error) {
	var client *ethrpc.Client
	if networkClients, _ := ethrpcClients[networkID]; len(networkClients) == 0 {
		erpc, err := ethrpc.Dial(rpcURL)
		if err != nil {
			Log.Warningf("Failed to dial RPC client for JSON-RPC host: %s", rpcURL)
			return nil, err
		}
		client = erpc
		ethrpcClients[networkID] = append(networkClients, client)
		Log.Debugf("Dialed JSON-RPC host @ %s", rpcURL)
	} else {
		client = ethrpcClients[networkID][0]
		Log.Debugf("Resolved JSON-RPC host @ %s", rpcURL)
	}
	return client, nil
}

// EncodeABI returns the ABI-encoded calldata for the given method and params
func EncodeABI(method *abi.Method, params ...interface{}) ([]byte, error) {
	var methodDescriptor = fmt.Sprintf("method %s", method.Name)
	Log.Debugf("Attempting to encode %d parameters prior to executing contract method: %s", len(params), methodDescriptor)
	var args []interface{}

	for i := range params {
		if i >= len(method.Inputs) {
			break
		}
		input := method.Inputs[i]
		Log.Debugf("Attempting to coerce encoding of %v abi parameter; value: %s", input.Type, params[i])
		param, err := coerceAbiParameter(input.Type, params[i])
		if err != nil {
			Log.Warningf("Failed to encode abi parameter %s in accordance with contract %s; %s", input.Name, methodDescriptor, err.Error())
		} else {
			switch reflect.TypeOf(param).Kind() {
			case reflect.String:
				param = []byte(param.(string))
			default:
				// no-op
				Log.Debugf("Unmodified parameter (type: %s); value: %s", input.Type, param)
			}

			args = append(args, param)
			Log.Debugf("Coerced encoding of %v abi parameter; value: %s", input.Type, param)
		}
	}

	encodedArgs, err := method.Inputs.Pack(args...)
	if err != nil {
		return nil, err
	}

	Log.Debugf("Encoded %v abi params prior to executing contract method: %s; abi-encoded arguments %v bytes packed", len(params), methodDescriptor, len(encodedArgs))
	return append(method.Id(), encodedArgs...), nil
}

// ExecuteContract builds valid calldata for signature and broadcasts a contract execution tx via JSON-RPC
func ExecuteContract(networkID, rpcURL, from string, to, data *string, val *big.Int, method string, contractABI interface{}, params []interface{}) (*interface{}, error) {
	// TODO: verify that to is a valid contract address
	var _abi *abi.ABI
	var err error
	if _, ok := contractABI.(*abi.ABI); ok {
		_abi = contractABI.(*abi.ABI)
	} else if _, ok := contractABI.(abi.ABI); ok {
		castAbi := contractABI.(abi.ABI)
		_abi = &castAbi
	} else {
		_abi, err = parseContractABI(contractABI)
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to execute contract method %s on contract %s; no ABI resolved: %s", method, *to, err.Error())
	}
	var methodDescriptor = fmt.Sprintf("method %s", method)
	var abiMethod *abi.Method
	if mthd, ok := _abi.Methods[method]; ok {
		abiMethod = &mthd
	} else if method == "" {
		abiMethod = &_abi.Constructor
		methodDescriptor = "constructor"
	}
	if abiMethod != nil {
		Log.Debugf("Attempting to encode %d parameters [ %s ] prior to executing %s on contract %s", len(params), params, methodDescriptor, to)
		invocationSig, err := EncodeABI(abiMethod, params...)
		if err != nil {
			return nil, fmt.Errorf("Failed to encode %d parameters prior to attempting execution of %s on contract %s; %s", len(params), methodDescriptor, *to, err.Error())
		}

		data := common.Bytes2Hex(invocationSig)

		if abiMethod.Const {
			Log.Debugf("Attempting to read constant method %s on contract: %s", method, to)
			client, err := DialJsonRpc(networkID, rpcURL)
			gasPrice, _ := client.SuggestGasPrice(context.TODO())
			msg := asCallMsg(from, stringOrNil(data), to, val, gasPrice.Uint64(), 0)
			result, _ := client.CallContract(context.TODO(), msg, nil)
			var out interface{}
			err = abiMethod.Outputs.Unpack(&out, result)
			if len(abiMethod.Outputs) == 1 {
				err = abiMethod.Outputs.Unpack(&out, result)
			} else if len(abiMethod.Outputs) > 1 {
				// handle tuple
				vals := make([]interface{}, len(abiMethod.Outputs))
				for i := range abiMethod.Outputs {
					typestr := fmt.Sprintf("%s", abiMethod.Outputs[i].Type)
					Log.Debugf("Reflectively adding type hint for unpacking %s in return values slot %v", typestr, i)
					typ, err := abi.NewType(typestr)
					if err != nil {
						return nil, fmt.Errorf("Failed to reflectively add appropriately-typed %s value for in return values slot %v); %s", typestr, i, err.Error())
					}
					vals[i] = reflect.New(typ.Type).Interface()
				}
				err = abiMethod.Outputs.Unpack(&vals, result)
				out = vals
				Log.Debugf("Unpacked %v returned values from read of constant %s on contract: %s; values: %s", len(vals), methodDescriptor, to, vals)
			}
			if err != nil {
				return nil, fmt.Errorf("Failed to read constant %s on contract: %s (signature with encoded parameters: %s); %s", methodDescriptor, *to, data, err.Error())
			}
			return &out, nil
		}
	} else {
		err = fmt.Errorf("Failed to execute contract %s on contract: %s; method not found in ABI", methodDescriptor, *to)
	}
	return nil, err
}

// GenerateKeyPair - creates and returns an ECDSA keypair;
// the returned *ecdsa.PrivateKey can be encoded with: hex.EncodeToString(ethcrypto.FromECDSA(privateKey))
func GenerateKeyPair() (address *string, privateKey *ecdsa.PrivateKey, err error) {
	privateKey, err = ethcrypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	address = stringOrNil(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex())
	return address, privateKey, nil
}

// MarshalKeyPairJSON - returns keystore JSON representation of given private key
func MarshalKeyPairJSON(addr common.Address, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	type keyJSON struct {
		ID         string `json:"id"`
		Address    string `json:"address"`
		PrivateKey string `json:"privatekey"`
		Version    int    `json:"version"`
	}
	keyUUID, _ := generateKeyUUID()
	key := keyJSON{
		ID:         keyUUID,
		Address:    hex.EncodeToString(addr[:]),
		PrivateKey: hex.EncodeToString(ethcrypto.FromECDSA(privateKey)),
		Version:    3,
	}
	return json.Marshal(key)
}

// MarshalEncryptedKey encrypts key as version 3.
func MarshalEncryptedKey(addr common.Address, privateKey *ecdsa.PrivateKey, secret string) ([]byte, error) {
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

	salt := randentropy.GetEntropyCSPRNG(32)
	derivedKey, err := scrypt.Key([]byte(secret), salt, LightScryptN, scryptR, LightScryptP, scryptDKLen)
	if err != nil {
		return nil, err
	}
	encryptKey := derivedKey[:16]
	keyBytes := ethcrypto.FromECDSA(privateKey)

	iv := randentropy.GetEntropyCSPRNG(aes.BlockSize) // 16
	cipherText, err := aesCTRXOR(encryptKey, keyBytes, iv)
	if err != nil {
		return nil, err
	}
	mac := ethcrypto.Keccak256(derivedKey[16:32], cipherText)

	keyUUID, _ := generateKeyUUID()

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

func generateKeyUUID() (string, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return "", err
	}
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[:4], u[4:6], u[6:8], u[8:10], u[10:]), nil
}

// HashFunctionSelector returns the first 4 bytes of the Keccak256 hash of the given function selector
func HashFunctionSelector(sel string) string {
	hash := Keccak256(sel)
	return common.Bytes2Hex(hash[0:4])
}

// Keccak256 hash the given string
func Keccak256(str string) []byte {
	return ethcrypto.Keccak256([]byte(str))
}

// Transaction broadcast helpers

// BroadcastTx injects a signed transaction into the pending pool for execution.
func BroadcastTx(ctx context.Context, networkID, rpcURL string, tx *types.Transaction, client *ethclient.Client, result interface{}) error {
	rpcClient, err := ResolveJsonRpcClient(networkID, rpcURL)
	if err != nil {
		return err
	}

	data, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return err
	}

	return rpcClient.CallContext(ctx, result, "eth_sendRawTransaction", common.ToHex(data))
}

// BroadcastSignedTx emits a given signed tx for inclusion in a block
func BroadcastSignedTx(networkID, rpcURL string, signedTx *types.Transaction) error {
	client, err := DialJsonRpc(networkID, rpcURL)
	if err != nil {
		return fmt.Errorf("Failed to dial JSON-RPC host; %s", err.Error())
	} else if signedTx != nil {
		Log.Debugf("Transmitting signed tx to JSON-RPC host")
		err = BroadcastTx(context.TODO(), networkID, rpcURL, signedTx, client, nil)
		if err != nil {
			return fmt.Errorf("Failed to transmit signed tx to JSON-RPC host; %s", err.Error())
		}
	}
	return nil
}

// SignTx signs a transaction using the given private key and calldata
func SignTx(networkID, rpcURL, from, privateKey string, to, data *string, val *big.Int) (*types.Transaction, *string, error) {
	client, err := ResolveEthClient(networkID, rpcURL)
	if err != nil {
		return nil, nil, err
	}
	_, err = GetSyncProgress(client)
	if err == nil {
		cfg := GetChainConfig(networkID, rpcURL)
		blockNumber, err := GetLatestBlock(networkID, rpcURL)
		if err != nil {
			return nil, nil, err
		}
		nonce, err := client.PendingNonceAt(context.TODO(), common.HexToAddress(from))
		if err != nil {
			return nil, nil, err
		}
		gasPrice, _ := client.SuggestGasPrice(context.TODO())
		var _data []byte
		if data != nil {
			_data = common.FromHex(*data)
		}
		var tx *types.Transaction
		if to != nil {
			addr := common.HexToAddress(*to)
			callMsg := asCallMsg(from, data, to, val, gasPrice.Uint64(), 0)
			gasLimit, err := client.EstimateGas(context.TODO(), callMsg)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to estimate gas for tx; %s", err.Error())
			}
			Log.Debugf("Estimated %d total gas required for tx with %d-byte data payload", gasLimit, len(_data))
			tx = types.NewTransaction(nonce, addr, val, gasLimit, gasPrice, _data)
		} else {
			Log.Debugf("Attempting to deploy contract via tx; estimating total gas requirements")
			callMsg := asCallMsg(from, data, to, val, gasPrice.Uint64(), 0)
			gasLimit, err := client.EstimateGas(context.TODO(), callMsg)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to estimate gas for tx; %s", err.Error())
			}
			Log.Debugf("Estimated %d total gas required for contract deployment tx with %d-byte data payload", gasLimit, len(_data))
			tx = types.NewContractCreation(nonce, val, gasLimit, gasPrice, _data)
		}
		signer := types.MakeSigner(cfg, big.NewInt(int64(blockNumber)))
		hash := signer.Hash(tx).Bytes()
		Log.Debugf("Signing tx on behalf of %s", from)
		_privateKey, err := ethcrypto.HexToECDSA(privateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed read private key bytes prior to signing tx; %s", err.Error())
		}
		sig, err := ethcrypto.Sign(hash, _privateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to sign tx on behalf of %s; %s", *to, err.Error())
		}
		if err == nil {
			signedTx, _ := tx.WithSignature(signer, sig)
			hash := stringOrNil(fmt.Sprintf("0x%x", signedTx.Hash()))
			signedTxJSON, _ := signedTx.MarshalJSON()
			Log.Debugf("Signed tx for broadcast via JSON-RPC: %s", signedTxJSON)
			return signedTx, hash, nil
		}
		return nil, nil, err
	}
	return nil, nil, err
}

// ABI-related helpers

func coerceAbiParameter(t abi.Type, v interface{}) (interface{}, error) {
	switch t.T {
	case abi.ArrayTy, abi.SliceTy:
		switch v.(type) {
		case []byte:
			return forEachUnpack(t, v.([]byte), 0, len(v.([]interface{}))-1)
		case string:
			return forEachUnpack(t, []byte(v.(string)), 0, len(v.(string)))
		default:
			// HACK-- this fallback for edge case handling isn't the cleanest
			typestr := fmt.Sprintf("%s", t)
			if typestr == "uint256[]" {
				Log.Debugf("Attempting fallback coercion of uint256[] abi parameter")
				vals := make([]*big.Int, t.Size)
				for _, val := range v.([]interface{}) {
					vals = append(vals, big.NewInt(int64(val.(float64))))
				}
				return vals, nil
			}
		}
	case abi.StringTy: // variable arrays are written at the end of the return bytes
		return string(v.([]byte)), nil
	case abi.IntTy, abi.UintTy:
		switch t.Kind {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return big.NewInt(int64(v.(int64))), nil
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return big.NewInt(int64(v.(int64))), nil
		case reflect.Float64:
			return big.NewInt(int64(v.(float64))), nil
		case reflect.Ptr:
			switch v.(type) {
			case float64:
				return big.NewInt(int64(v.(float64))), nil
			}
		default:
			return readInteger(t.Kind, v.([]byte)), nil
		}
	case abi.BoolTy:
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
		return v, nil
	case abi.FixedBytesTy:
		return readFixedBytes(t, []byte(v.(string)))
	case abi.FunctionTy:
		return readFunctionType(t, v.([]byte))
	default:
		// no-op
	}
	return nil, fmt.Errorf("Failed to coerce %s parameter for abi encoding; unhandled type: %v", t.String(), t)
}

// iteratively unpack elements
func forEachUnpack(t abi.Type, output []byte, start, size int) (interface{}, error) {
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
		refSlice = reflect.MakeSlice(t.Type, size, size)
	} else if t.T == abi.ArrayTy {
		// declare our array
		refSlice = reflect.New(t.Type).Elem()
	} else {
		return nil, fmt.Errorf("abi: invalid type in array/slice unpacking stage")
	}

	// Arrays have packed elements, resulting in longer unpack steps.
	// Slices have just 32 bytes per element (pointing to the contents).
	elemSize := 32
	if t.T == abi.ArrayTy {
		elemSize = getFullElemSize(t.Elem)
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
func readInteger(kind reflect.Kind, b []byte) interface{} {
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
func readFunctionType(t abi.Type, word []byte) (funcTy [24]byte, err error) {
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
func readFixedBytes(t abi.Type, word []byte) (interface{}, error) {
	if t.T != abi.FixedBytesTy {
		return nil, fmt.Errorf("abi: invalid type in call to make fixed byte array")
	}

	Log.Debugf("Attempting to read fixed bytes in accordance with Ethereum contract ABI; type: %v; word: %s", t, word)

	// convert
	array := reflect.New(t.Type).Elem()
	reflect.Copy(array, reflect.ValueOf(word))
	return array.Interface(), nil
}

func requiresLengthPrefix(t *abi.Type) bool {
	return t.T == abi.StringTy || t.T == abi.BytesTy || t.T == abi.SliceTy
}

func getFullElemSize(elem *abi.Type) int {
	//all other should be counted as 32 (slices have pointers to respective elements)
	size := 32
	//arrays wrap it, each element being the same size
	for elem.T == abi.ArrayTy {
		size *= elem.Size
		elem = elem.Elem
	}
	return size
}

func lengthPrefixPointsTo(index int, output []byte) (start int, length int, err error) {
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

func readBool(word []byte) (bool, error) {
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

func asCallMsg(from string, data, to *string, val *big.Int, gasPrice, gasLimit uint64) ethereum.CallMsg {
	var _to *common.Address
	var _data []byte
	if to != nil {
		addr := common.HexToAddress(*to)
		_to = &addr
	}
	if data != nil {
		_data = common.FromHex(*data)
	}
	return ethereum.CallMsg{
		From:     common.HexToAddress(from),
		To:       _to,
		Gas:      gasLimit,
		GasPrice: big.NewInt(int64(gasPrice)),
		Value:    val,
		Data:     _data,
	}
}

func parseContractABI(contractAbi interface{}) (*abi.ABI, error) {
	abistr, err := json.Marshal(contractAbi)
	if err != nil {
		Log.Warningf("Failed to marshal ABI from contract params to json; %s", err.Error())
		return nil, err
	}

	abival, err := abi.JSON(strings.NewReader(string(abistr)))
	if err != nil {
		Log.Warningf("Failed to initialize ABI from contract  params to json; %s", err.Error())
		return nil, err
	}

	return &abival, nil
}
