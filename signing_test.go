package provide

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/assert"
)

func TestAddValidator(t *testing.T) {
	networkConsensusABI, _ := parseNetworkConsensusABI()
	var _params []interface{}
	_params = append(_params, "0x87b7af6915fa56a837fa85e31ad6a450c41e8fab")
	_, err := ExecuteContract("somenetwork", "http://localhost:8050", "0x5973137aB0b0C8B11b88a8CB32aBE13ADC81809F", stringOrNil("0x0000000000000000000000000000000000000018"), stringOrNil("5b7b13d830f7c9a85fa9930fafd8897799c569974b5240ba30e6ace7e2a395dd"), nil, nil, "addValidator", networkConsensusABI, _params)
	assert.Nil(t, err)
}

func readCachedChainspecABI() ([]byte, error) {
	var abi []byte
	var err error
	chainspecABIPath := "/Users/kt/code/provide.network/network-consensus-e2e-testsuite/.tmp/spec.abi.json"
	if _, err = os.Stat(chainspecABIPath); err == nil {
		abi, err = ioutil.ReadFile(chainspecABIPath)
	}
	return abi, err
}

func parseNetworkConsensusABI() (abi.ABI, error) {
	cachedABI, err := readCachedChainspecABI()
	if err == nil {
		var chainspecABI map[string]interface{}
		err = json.Unmarshal(cachedABI, &chainspecABI)
		if err == nil {
			abiJSON, err := json.Marshal(chainspecABI["0x0000000000000000000000000000000000000018"])
			if err == nil {
				return abi.JSON(strings.NewReader(string(abiJSON)))
			}
		}
	}
	return abi.ABI{}, err
}
