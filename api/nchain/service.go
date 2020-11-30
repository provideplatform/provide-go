package nchain

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/common"
)

const defaultNChainHost = "nchain.provide.services"
const defaultNChainPath = "api/v1"
const defaultNChainScheme = "https"

// Service for the nchain api
type Service struct {
	api.Client
}

// InitNChainService convenience method to initialize an `nchain.Service` instance
func InitNChainService(token string) *Service {
	host := defaultNChainHost
	if os.Getenv("NCHAIN_API_HOST") != "" {
		host = os.Getenv("NCHAIN_API_HOST")
	}

	path := defaultNChainPath
	if os.Getenv("NCHAIN_API_PATH") != "" {
		host = os.Getenv("NCHAIN_API_PATH")
	}

	scheme := defaultNChainScheme
	if os.Getenv("NCHAIN_API_SCHEME") != "" {
		scheme = os.Getenv("NCHAIN_API_SCHEME")
	}

	return &Service{
		api.Client{
			Host:   host,
			Path:   path,
			Scheme: scheme,
			Token:  common.StringOrNil(token),
		},
	}
}

// CreateAccount creates a new account
func CreateAccount(token string, params map[string]interface{}) (*Account, error) {
	uri := "accounts"
	status, resp, err := InitNChainService(token).Post(uri, params)

	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create account. status: %v", status)
	}

	account := &Account{}
	accountRaw, _ := json.Marshal(resp)
	err = json.Unmarshal(accountRaw, &account)
	if err != nil {
		return nil, fmt.Errorf("failed to create account. status: %v; %s", status, err.Error())
	}

	return account, nil
}

// ListAccounts
func ListAccounts(token string, params map[string]interface{}) ([]*Account, error) {
	status, resp, err := InitNChainService(token).Get("accounts", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list accounts; status: %v", status)
	}

	accounts := make([]*Account, 0)
	for _, item := range resp.([]interface{}) {
		account := &Account{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &account)
		accounts = append(accounts, account)
	}
	return accounts, nil
}

// GetAccountDetails
func GetAccountDetails(token, accountID string, params map[string]interface{}) (*Account, error) {
	uri := fmt.Sprintf("accounts/%s", accountID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch account; status: %v", status)
	}

	account := &Account{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &account)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch account; status: %v; %s", status, err.Error())
	}

	return account, nil
}

// GetAccountBalance
func GetAccountBalance(token, accountID, tokenID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("accounts/%s/balances/%s", accountID, tokenID)
	return InitNChainService(token).Get(uri, params)
}

// CreateBridge
func CreateBridge(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitNChainService(token).Post("bridges", params)
}

// ListBridges
func ListBridges(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitNChainService(token).Get("bridges", params)
}

// GetBridgeDetails
func GetBridgeDetails(token, bridgeID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("bridges/%s", bridgeID)
	return InitNChainService(token).Get(uri, params)
}

// CreateConnector
func CreateConnector(token string, params map[string]interface{}) (*Connector, error) {
	status, resp, err := InitNChainService(token).Post("connectors", params)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create connector; status: %v", status)
	}

	connector := &Connector{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &connector)
	if err != nil {
		return nil, fmt.Errorf("failed to create connector; status: %v; %s", status, err.Error())
	}

	return connector, nil
}

// ListConnectors
func ListConnectors(token string, params map[string]interface{}) ([]*Connector, error) {
	status, resp, err := InitNChainService(token).Get("connectors", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list connectors; status: %v", status)
	}

	connectors := make([]*Connector, 0)
	for _, item := range resp.([]interface{}) {
		connector := &Connector{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &connector)
		connectors = append(connectors, connector)
	}
	return connectors, nil
}

// GetConnectorDetails
func GetConnectorDetails(token, connectorID string, params map[string]interface{}) (*Connector, error) {
	uri := fmt.Sprintf("connectors/%s", connectorID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch connector; status: %v", status)
	}

	connector := &Connector{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &connector)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch connector; status: %v; %s", status, err.Error())
	}

	return connector, nil
}

// DeleteConnector
func DeleteConnector(token, connectorID string) error {
	uri := fmt.Sprintf("connectors/%s", connectorID)
	status, _, err := InitNChainService(token).Delete(uri)
	if err != nil {
		return err
	}

	if status != 204 {
		return fmt.Errorf("failed to delete connector; status: %v", status)
	}

	return nil
}

// CreateContract
func CreateContract(token string, params map[string]interface{}) (*Contract, error) {
	status, resp, err := InitNChainService(token).Post("contracts", params)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create contract; status %v", status)
	}

	contract := &Contract{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &contract)
	if err != nil {
		return nil, fmt.Errorf("failed to create contract; status: %v; %s", status, err.Error())
	}

	return contract, nil
}

// ExecuteContract
func ExecuteContract(token, contractID string, params map[string]interface{}) (*ContractExecutionResponse, error) {
	uri := fmt.Sprintf("contracts/%s/execute", contractID)
	status, resp, err := InitNChainService(token).Post(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 && status != 202 {
		return nil, fmt.Errorf("failed to execute contract; status %v", status)
	}

	execResponse := &ContractExecutionResponse{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &execResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to execute contract; status: %v; %s", status, err.Error())
	}

	return execResponse, nil
}

// ListContracts
func ListContracts(token string, params map[string]interface{}) ([]*Contract, error) {
	status, resp, err := InitNChainService(token).Get("contracts", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list contracts; status: %v", status)
	}

	contracts := make([]*Contract, 0)
	for _, item := range resp.([]interface{}) {
		contract := &Contract{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &contract)
		contracts = append(contracts, contract)
	}
	return contracts, nil
}

// GetContractDetails
func GetContractDetails(token, contractID string, params map[string]interface{}) (*Contract, error) {
	uri := fmt.Sprintf("contracts/%s", contractID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch contract; status %v", status)
	}

	contract := &Contract{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &contract)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch contract; status: %v; %s", status, err.Error())
	}

	return contract, nil
}

// CreateNetwork creates a new network
func CreateNetwork(token string, params map[string]interface{}) (*Network, error) {
	status, resp, err := InitNChainService(token).Post("networks", params)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create network; status: %v", status)
	}

	network := &Network{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &network)
	if err != nil {
		return nil, fmt.Errorf("failed to create network; status: %v; %s", status, err.Error())
	}

	return network, nil
}

// UpdateNetwork updates an existing network
func UpdateNetwork(token, networkID string, params map[string]interface{}) error {
	uri := fmt.Sprintf("networks/%s", networkID)
	status, _, err := InitNChainService(token).Put(uri, params)
	if err != nil {
		return err
	}

	if status != 204 {
		return fmt.Errorf("failed to fetch network. status %v", status)
	}

	return nil

}

// ListNetworks
func ListNetworks(token string, params map[string]interface{}) ([]*Network, error) {
	uri := fmt.Sprintf("networks")
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list networks. status: %v", status)
	}

	networks := make([]*Network, 0)
	for _, item := range resp.([]interface{}) {
		netwrk := &Network{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &netwrk)
		networks = append(networks, netwrk)
	}
	return networks, nil
}

// GetNetworkDetails returns the details for the specified network id
func GetNetworkDetails(token, networkID string, params map[string]interface{}) (*Network, error) {
	uri := fmt.Sprintf("networks/%s", networkID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch network. status %v", status)
	}

	network := &Network{}
	networkRaw, _ := json.Marshal(resp)
	err = json.Unmarshal(networkRaw, &network)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch network details. status: %v; %s", status, err.Error())
	}

	return network, nil
}

// ListNetworkAccounts
func ListNetworkAccounts(token, networkID string, params map[string]interface{}) ([]*Account, error) {
	uri := fmt.Sprintf("networks/%s/accounts", networkID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list accounts; status: %v", status)
	}

	accounts := make([]*Account, 0)
	for _, item := range resp.([]interface{}) {
		account := &Account{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &account)
		accounts = append(accounts, account)
	}
	return accounts, nil
}

// ListNetworkBlocks
func ListNetworkBlocks(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/blocks", networkID)
	return InitNChainService(token).Get(uri, params)
}

// ListNetworkBridges
func ListNetworkBridges(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/bridges", networkID)
	return InitNChainService(token).Get(uri, params)
}

// ListNetworkConnectors
func ListNetworkConnectors(token, networkID string, params map[string]interface{}) ([]*Connector, error) {
	uri := fmt.Sprintf("networks/%s/connectors", networkID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list connectors; status: %v", status)
	}

	connectors := make([]*Connector, 0)
	for _, item := range resp.([]interface{}) {
		connector := &Connector{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &connector)
		connectors = append(connectors, connector)
	}
	return connectors, nil
}

// ListNetworkContracts
func ListNetworkContracts(token, networkID string, params map[string]interface{}) ([]*Contract, error) {
	uri := fmt.Sprintf("networks/%s/contracts", networkID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list contracts; status: %v", status)
	}

	contracts := make([]*Contract, 0)
	for _, item := range resp.([]interface{}) {
		contract := &Contract{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &contract)
		contracts = append(contracts, contract)
	}
	return contracts, nil
}

// GetNetworkContractDetails
func GetNetworkContractDetails(token, networkID, contractID string, params map[string]interface{}) (*Contract, error) {
	uri := fmt.Sprintf("networks/%s/contracts/%s", networkID, contractID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch contract; status %v", status)
	}

	contract := &Contract{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &contract)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch contract; status: %v; %s", status, err.Error())
	}

	return contract, nil
}

// ListNetworkOracles
func ListNetworkOracles(token, networkID string, params map[string]interface{}) ([]*Oracle, error) {
	uri := fmt.Sprintf("networks/%s/oracles", networkID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list oracles; status: %v", status)
	}

	oracles := make([]*Oracle, 0)
	for _, item := range resp.([]interface{}) {
		oracle := &Oracle{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &oracle)
		oracles = append(oracles, oracle)
	}
	return oracles, nil
}

// ListNetworkTokens
func ListNetworkTokens(token, networkID string, params map[string]interface{}) ([]*Token, error) {
	uri := fmt.Sprintf("networks/%s/tokens", networkID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list token contracts; status: %v", status)
	}

	tknContracts := make([]*Token, 0)
	for _, item := range resp.([]interface{}) {
		tknContract := &Token{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &tknContract)
		tknContracts = append(tknContracts, tknContract)
	}
	return tknContracts, nil
}

// ListNetworkTransactions
func ListNetworkTransactions(token, networkID string, params map[string]interface{}) ([]*Transaction, error) {
	uri := fmt.Sprintf("networks/%s/transactions", networkID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list transactions; status: %v", status)
	}

	txs := make([]*Transaction, 0)
	for _, item := range resp.([]interface{}) {
		tx := &Transaction{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &tx)
		txs = append(txs, tx)
	}
	return txs, nil
}

// GetNetworkTransactionDetails
func GetNetworkTransactionDetails(token, networkID, txID string, params map[string]interface{}) (*Transaction, error) {
	uri := fmt.Sprintf("networks/%s/transactions/%s", networkID, txID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch tx; status %v", status)
	}

	tx := &Transaction{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &tx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tx; status: %v; %s", status, err.Error())
	}

	return tx, nil
}

// GetNetworkStatusMeta returns the status details for the specified network
func GetNetworkStatusMeta(token, networkID string, params map[string]interface{}) (*NetworkStatus, error) {
	uri := fmt.Sprintf("networks/%s/status", networkID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch network. status %v", status)
	}

	networkStatus := &NetworkStatus{}
	networkStatusRaw, _ := json.Marshal(resp)
	err = json.Unmarshal(networkStatusRaw, &networkStatus)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch network status. status: %v; %s", status, err.Error())
	}

	return networkStatus, nil
}

// CreateOracle
func CreateOracle(token string, params map[string]interface{}) (*Oracle, error) {
	status, resp, err := InitNChainService(token).Post("oracles", params)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create oracle; status: %v", status)
	}

	oracle := &Oracle{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &oracle)
	if err != nil {
		return nil, fmt.Errorf("failed to create oracle; status: %v; %s", status, err.Error())
	}

	return oracle, nil
}

// ListOracles
func ListOracles(token string, params map[string]interface{}) ([]*Oracle, error) {
	status, resp, err := InitNChainService(token).Get("oracles", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list oracles; status: %v", status)
	}

	oracles := make([]*Oracle, 0)
	for _, item := range resp.([]interface{}) {
		oracle := &Oracle{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &oracle)
		oracles = append(oracles, oracle)
	}
	return oracles, nil
}

// GetOracleDetails
func GetOracleDetails(token, oracleID string, params map[string]interface{}) (*Oracle, error) {
	uri := fmt.Sprintf("oracles/%s", oracleID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch oracle; status %v", status)
	}

	oracle := &Oracle{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &oracle)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch oracle; status: %v; %s", status, err.Error())
	}

	return oracle, nil
}

// CreateTokenContract
func CreateTokenContract(token string, params map[string]interface{}) (*Token, error) {
	status, resp, err := InitNChainService(token).Post("tokens", params)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create token contract; status: %v", status)
	}

	tkn := &Token{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &tkn)
	if err != nil {
		return nil, fmt.Errorf("failed to create token contract; status: %v; %s", status, err.Error())
	}

	return tkn, nil
}

// ListTokenContracts
func ListTokenContracts(token string, params map[string]interface{}) ([]*Token, error) {
	status, resp, err := InitNChainService(token).Get("tokens", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list token contracts; status: %v", status)
	}

	tknContracts := make([]*Token, 0)
	for _, item := range resp.([]interface{}) {
		tknContract := &Token{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &tknContract)
		tknContracts = append(tknContracts, tknContract)
	}
	return tknContracts, nil
}

// GetTokenContractDetails
func GetTokenContractDetails(token, tokenID string, params map[string]interface{}) (*Token, error) {
	uri := fmt.Sprintf("tokens/%s", tokenID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch token contract; status %v", status)
	}

	tknContract := &Token{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &tknContract)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch token contract; status: %v; %s", status, err.Error())
	}

	return tknContract, nil
}

// CreateTransaction
func CreateTransaction(token string, params map[string]interface{}) (*Transaction, error) {
	status, resp, err := InitNChainService(token).Post("transactions", params)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create tx; status: %v", status)
	}

	tx := &Transaction{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &tx)
	if err != nil {
		return nil, fmt.Errorf("failed to create tx; status: %v; %s", status, err.Error())
	}

	return tx, nil
}

// ListTransactions
func ListTransactions(token string, params map[string]interface{}) ([]*Transaction, error) {
	status, resp, err := InitNChainService(token).Get("transactions", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list transactions; status: %v", status)
	}

	txs := make([]*Transaction, 0)
	for _, item := range resp.([]interface{}) {
		tx := &Transaction{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &tx)
		txs = append(txs, tx)
	}
	return txs, nil
}

// GetTransactionDetails
func GetTransactionDetails(token, txID string, params map[string]interface{}) (*Transaction, error) {
	uri := fmt.Sprintf("transactions/%s", txID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch tx; status %v", status)
	}

	tx := &Transaction{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &tx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tx; status: %v; %s", status, err.Error())
	}

	return tx, nil
}

// CreateWallet
func CreateWallet(token string, params map[string]interface{}) (*Wallet, error) {
	status, resp, err := InitNChainService(token).Post("wallets", params)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create wallet; status: %v", status)
	}

	wallet := &Wallet{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &wallet)
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet; status: %v; %s", status, err.Error())
	}

	return wallet, nil
}

// ListWallets
func ListWallets(token string, params map[string]interface{}) ([]*Wallet, error) {
	status, resp, err := InitNChainService(token).Get("wallets", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list wallets; status: %v", status)
	}

	wallets := make([]*Wallet, 0)
	for _, item := range resp.([]interface{}) {
		wallet := &Wallet{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &wallet)
		wallets = append(wallets, wallet)
	}
	return wallets, nil
}

// GetWalletDetails
func GetWalletDetails(token, walletID string, params map[string]interface{}) (*Wallet, error) {
	uri := fmt.Sprintf("wallets/%s", walletID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch wallet; status %v", status)
	}

	wallet := &Wallet{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &wallet)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch wallet; status: %v; %s", status, err.Error())
	}

	return wallet, nil
}

// ListWalletAccounts
func ListWalletAccounts(token, walletID string, params map[string]interface{}) ([]*Account, error) {
	uri := fmt.Sprintf("wallets/%s/accounts", walletID)
	status, resp, err := InitNChainService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list accounts; status: %v", status)
	}

	accounts := make([]*Account, 0)
	for _, item := range resp.([]interface{}) {
		account := &Account{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &account)
		accounts = append(accounts, account)
	}
	return accounts, nil
}
