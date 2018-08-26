package provide

import "fmt"

// Goldmine client
type Goldmine struct {
	APIClient
}

// InitGoldmine convenience method
func InitGoldmine(token string) *Goldmine {
	return &Goldmine{
		APIClient{
			Host:   "goldmine.provide.services",
			Path:   "api/v1",
			Scheme: "https",
			Token:  stringOrNil(token),
		},
	}
}

// CreateBridge
func CreateBridge(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).post("bridges", params)
}

// ListBridges
func ListBridges(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).get("bridges", params)
}

// GetBridgeDetails
func GetBridgeDetails(token, bridgeID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("bridges/%s", bridgeID)
	return InitGoldmine(token).get(uri, params)
}

// CreateConnector
func CreateConnector(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).post("connectors", params)
}

// ListConnectors
func ListConnectors(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).get("connectors", params)
}

// GetConnectorDetails
func GetConnectorDetails(token, connectorID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("connectors/%s", connectorID)
	return InitGoldmine(token).get(uri, params)
}

// DeleteConnector
func DeleteConnector(token, connectorID string) (int, interface{}, error) {
	uri := fmt.Sprintf("connectors/%s", connectorID)
	return InitIdent(stringOrNil(token)).delete(uri)
}

// CreateContract
func CreateContract(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).post("contracts", params)
}

// ExecuteContract
func ExecuteContract(token, contractID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("contracts/%s/execute", contractID)
	return InitGoldmine(token).post(uri, params)
}

// ListContracts
func ListContracts(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).get("contracts", params)
}

// GetContractDetails
func GetContractDetails(token, contractID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("contracts/%s", contractID)
	return InitGoldmine(token).get(uri, params)
}

// CreateNetwork
func CreateNetwork(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).post("networks", params)
}

// UpdateNetwork updates an existing network
func UpdateNetwork(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s", networkID)
	return InitIdent(stringOrNil(token)).put(uri, params)
}

// ListNetworks
func ListNetworks(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).get("networks", params)
}

// GetNetworkDetails
func GetNetworkDetails(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s", networkID)
	return InitGoldmine(token).get(uri, params)
}

// ListNetworkAccounts
func ListNetworkAccounts(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/accounts", networkID)
	return InitGoldmine(token).get(uri, params)
}

// ListNetworkBlocks
func ListNetworkBlocks(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/blocks", networkID)
	return InitGoldmine(token).get(uri, params)
}

// ListNetworkBridges
func ListNetworkBridges(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/bridges", networkID)
	return InitGoldmine(token).get(uri, params)
}

// ListNetworkConnectors
func ListNetworkConnectors(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/connectors", networkID)
	return InitGoldmine(token).get(uri, params)
}

// ListNetworkContracts
func ListNetworkContracts(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/contracts", networkID)
	return InitGoldmine(token).get(uri, params)
}

// GetNetworkContractDetails
func GetNetworkContractDetails(token, networkID, contractID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/contracts/%s", networkID, contractID)
	return InitGoldmine(token).get(uri, params)
}

// ListNetworkOracles
func ListNetworkOracles(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/oracles", networkID)
	return InitGoldmine(token).get(uri, params)
}

// ListNetworkTokens
func ListNetworkTokens(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/tokens", networkID)
	return InitGoldmine(token).get(uri, params)
}

// ListNetworkTransactions
func ListNetworkTransactions(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/transactions", networkID)
	return InitGoldmine(token).get(uri, params)
}

// GetNetworkTransactionDetails
func GetNetworkTransactionDetails(token, networkID, txID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/transactions/%s", networkID, txID)
	return InitGoldmine(token).get(uri, params)
}

// GetNetworkStatusMeta
func GetNetworkStatusMeta(token, networkID, txID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/status", networkID, txID)
	return InitGoldmine(token).get(uri, params)
}

// ListNetworkNodes
func ListNetworkNodes(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/nodes", networkID)
	return InitGoldmine(token).get(uri, params)
}

// CreateNetworkNode
func CreateNetworkNode(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/nodes", networkID)
	return InitGoldmine(token).post(uri, params)
}

// GetNetworkNodeDetails
func GetNetworkNodeDetails(token, networkID, nodeID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/nodes/%s", networkID, nodeID)
	return InitGoldmine(token).get(uri, params)
}

// GetNetworkNodeLogs
func GetNetworkNodeLogs(token, networkID, nodeID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/nodes/%s/logs", networkID, nodeID)
	return InitGoldmine(token).get(uri, params)
}

// DeleteNetworkNode
func DeleteNetworkNode(token, networkID, nodeID string) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/nodes/%s", networkID, nodeID)
	return InitIdent(stringOrNil(token)).delete(uri)
}

// CreateOracle
func CreateOracle(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).post("oracles", params)
}

// ListOracles
func ListOracles(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).get("oracles", params)
}

// GetOracleDetails
func GetOracleDetails(token, oracleID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("oracles/%s", oracleID)
	return InitGoldmine(token).get(uri, params)
}

// CreateTokenContract
func CreateTokenContract(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).post("tokens", params)
}

// ListTokenContracts
func ListTokenContracts(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).get("tokens", params)
}

// GetTokenContractDetails
func GetTokenContractDetails(token, tokenID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("tokens/%s", tokenID)
	return InitGoldmine(token).get(uri, params)
}

// CreateTransaction
func CreateTransaction(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).post("transactions", params)
}

// ListTransactions
func ListTransactions(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).get("transactions", params)
}

// GetTransactionDetails
func GetTransactionDetails(token, txID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("transactions/%s", txID)
	return InitGoldmine(token).get(uri, params)
}

// CreateWallet
func CreateWallet(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).post("wallets", params)
}

// ListWallets
func ListWallets(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitGoldmine(token).get("wallets", params)
}

// GetWalletDetails
func GetWalletDetails(token, walletID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("wallets/%s", walletID)
	return InitGoldmine(token).get(uri, params)
}

// GetWalletBalance
func GetWalletBalance(token, walletID, tokenID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("wallets/%s/balances/%s", walletID, tokenID)
	return InitGoldmine(token).get(uri, params)
}
